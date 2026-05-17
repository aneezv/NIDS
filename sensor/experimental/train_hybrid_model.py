import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# =============================================================================
# HYBRID MODEL — RandomForest + IsolationForest
#
# How the two models work together:
#
#   RandomForest  → supervised, trained on labeled normal/attack data
#                   HIGH precision on known attack types
#                   Output: attack probability 0.0–1.0
#
#   IsolationForest → unsupervised, trained on NORMAL data only
#                     Catches novel/unknown attacks by spotting anomalies
#                     Output: anomaly score 0.0–1.0 (higher = more anomalous)
#
# Decision rule (avoids IF re-introducing false positives):
#   ALERT if:
#     rf_prob >= RF_THRESHOLD                        ← RF confident it's an attack
#     OR
#     anomaly_score >= IF_THRESHOLD                  ← IF sees something very weird
#     AND rf_prob >= RF_UNSURE_MIN                   ← AND RF isn't sure it's normal
#
# This means IsolationForest only speaks when RF is uncertain. It cannot
# override RF when RF is confident something is normal.
# =============================================================================

RF_THRESHOLD   = 0.55   # RF attack probability to trigger alert (lower = more sensitive)
IF_THRESHOLD   = 0.72   # IF anomaly score to trigger alert     (higher = less noisy)
RF_UNSURE_MIN  = 0.25   # IF only activates if RF prob is above this (not clearly normal)

rng = np.random.default_rng(42)

# ─────────────────────────────────────────────────────────────────────────────
# Data generation helper
# ─────────────────────────────────────────────────────────────────────────────

def make(n, frame_len, port, proto, flags, pkt_rate, byte_rate,
         conn_dur=None, upload_ratio=None, label=0):
    def r(v):
        if callable(v):                      return v(n)
        if isinstance(v, (list, np.ndarray)): return rng.choice(v, n)
        return np.full(n, v)
    return {
        'frame_len':     r(frame_len),
        'port':          r(port),
        'proto':         r(proto),
        'flags':         r(flags),
        'packet_rate':   r(pkt_rate),
        'byte_rate':     r(byte_rate),
        'conn_duration': r(conn_dur)      if conn_dur      is not None else rng.uniform(0.5, 30, n),
        'upload_ratio':  r(upload_ratio)  if upload_ratio  is not None else np.full(n, 0.1),
        'label': np.full(n, label),
    }

U = lambda lo, hi: (lambda n: rng.uniform(lo, hi, n))
I = lambda lo, hi: (lambda n: rng.integers(lo, hi, n))
C = lambda arr:    (lambda n: rng.choice(arr, n))

# ─────────────────────────────────────────────────────────────────────────────
# NORMAL TRAFFIC  (label = 0)
# ─────────────────────────────────────────────────────────────────────────────

normal = [
    make(15000, [1400,1500], [80,443,27015], 6, 0x10,
         U(1000,50000), U(1_500_000,100_000_000),
         conn_dur=U(5,120), upload_ratio=U(0.01,0.05)),

    make(10000, [1200,1400,1500], 443, [6,17], [0x10,0],
         U(500,5000), U(600_000,8_000_000),
         conn_dur=U(30,3600), upload_ratio=U(0.01,0.04)),

    make(8000, [60,512,1000,1500], [443,80], 6, [0x10,0x18],
         U(200,3000), U(100_000,15_000_000),
         conn_dur=U(0.1,5), upload_ratio=U(0.05,0.2)),

    make(8000, [60,128,256], [443,80], 6, [0x10,0x18],
         U(1,50), U(100,50_000),
         conn_dur=U(5,300), upload_ratio=U(0.05,0.3)),

    make(5000, [60,64,80,128], 53, 17, 0,
         U(0.5,50), U(30,6400),
         conn_dur=U(0.01,0.5), upload_ratio=U(0.3,0.6)),

    make(6000, [40,64,128,300], 443, 6, [0x02,0x12,0x10,0x18],
         U(5,300), U(200,120_000),
         conn_dur=U(0.05,2), upload_ratio=U(0.3,0.6)),

    make(10000, [64,128,256], I(10000,30000), 17, 0,
         U(20,128), U(1200,32_768),
         conn_dur=U(60,7200), upload_ratio=U(0.3,0.5)),

    make(2000, 64, 0, 1, 0,
         U(0.5,10), U(32,640),
         conn_dur=U(0.1,10), upload_ratio=U(0.45,0.55)),

    make(3000, [60,64,128,300], [123,1900,5353,67,68], [17,1], 0,
         U(0.01,5), U(1,1500),
         conn_dur=U(0.01,1), upload_ratio=U(0.1,0.9)),

    # Normal large upload (cloud backup, video call) — critical to avoid exfil false positives
    make(4000, [1400,1500], [443,80], 6, [0x10,0x18],
         U(100,5000), U(500_000,20_000_000),
         conn_dur=U(10,600), upload_ratio=U(0.5,0.95)),
]

# ─────────────────────────────────────────────────────────────────────────────
# ATTACK TRAFFIC  (label = 1)
# ─────────────────────────────────────────────────────────────────────────────

attacks = [
    # Floods
    make(3000, 64, 0, 1, 0,
         U(3000,100_000), U(192_000,6_400_000),
         conn_dur=U(1,60), upload_ratio=U(0.45,0.55), label=1),

    make(3000, [40,60], I(1,1024), 6, 0x02,
         U(1000,80_000), U(40_000,4_800_000),
         conn_dur=U(1,30), upload_ratio=U(0.8,1.0), label=1),

    make(3000, [64,512,1500], I(1,65535), 17, 0,
         U(2000,100_000), U(128_000,150_000_000),
         conn_dur=U(1,60), upload_ratio=U(0.8,1.0), label=1),

    make(2000, [1400,1500], [80,443], 6, 0x18,
         U(2000,30_000), U(2_800_000,45_000_000),
         conn_dur=U(1,30), upload_ratio=U(0.7,0.95), label=1),

    # Port scans
    make(3000, [40,44,60], I(1,65535), 6, 0x02,
         U(100,5000), U(4000,300_000),
         conn_dur=U(0.01,5), upload_ratio=U(0.85,1.0), label=1),

    make(2000, [40,44], I(1,65535), 6, 0x02,
         U(0.05,2), U(2,80),
         conn_dur=U(60,3600), upload_ratio=U(0.9,1.0), label=1),

    # DNS amplification
    make(2000, [512,1000,1500], 53, 17, 0,
         U(500,10_000), U(256_000,15_000_000),
         conn_dur=U(1,30), upload_ratio=U(0.0,0.1), label=1),

    # Slowloris — very long connection, near-zero rate, high upload ratio
    make(3000, [64,128,200], [80,443], 6, [0x10,0x18],
         U(0.03,0.3), U(10,500),
         conn_dur=U(200,7200), upload_ratio=U(0.6,0.9), label=1),

    # Data exfiltration — sustained high upload ratio
    make(2000, [1400,1500], C([443,8443,4444,8080,9001]), 6, [0x10,0x18],
         U(50,2000), U(500_000,15_000_000),
         conn_dur=U(60,3600), upload_ratio=U(0.85,0.99), label=1),

    # DNS exfiltration
    make(1500, [128,200,256], 53, 17, 0,
         U(5,100), U(5000,200_000),
         conn_dur=U(10,600), upload_ratio=U(0.7,0.95), label=1),
]

# ─────────────────────────────────────────────────────────────────────────────
# Assemble dataset
# ─────────────────────────────────────────────────────────────────────────────

feature_cols = ['frame_len','port','proto','flags','packet_rate','byte_rate',
                'conn_duration','upload_ratio']

df_all    = pd.concat([pd.DataFrame(d) for d in normal + attacks], ignore_index=True)
df_normal = pd.concat([pd.DataFrame(d) for d in normal], ignore_index=True)
df_all    = df_all.sample(frac=1, random_state=42).reset_index(drop=True)

X = df_all[feature_cols]
y = df_all['label']
X_normal = df_normal[feature_cols]

print(f"Normal samples : {(y==0).sum():,}")
print(f"Attack samples : {(y==1).sum():,}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

# Normal-only training set for IsolationForest
X_train_normal = X_train[y_train == 0]

# ─────────────────────────────────────────────────────────────────────────────
# Train the scaler once — shared by both models so scores are comparable
# ─────────────────────────────────────────────────────────────────────────────

scaler = RobustScaler()
X_train_scaled        = scaler.fit_transform(X_train)
X_train_normal_scaled = scaler.transform(X_train_normal)
X_test_scaled         = scaler.transform(X_test)

# ─────────────────────────────────────────────────────────────────────────────
# Model 1 — RandomForest (supervised, known attacks)
# ─────────────────────────────────────────────────────────────────────────────

print("\nTraining RandomForest...")
rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_leaf=5,
    class_weight='balanced',
    n_jobs=-1,
    random_state=42,
)
rf.fit(X_train_scaled, y_train)

# ─────────────────────────────────────────────────────────────────────────────
# Model 2 — IsolationForest (unsupervised, trained on NORMAL only)
#
# Trained on normal traffic only so it learns the boundary of "normal".
# Anything outside that boundary gets a high anomaly score — including
# attack types that were never in the labeled training data.
# ─────────────────────────────────────────────────────────────────────────────

print("Training IsolationForest on normal traffic only...")
iso = IsolationForest(
    n_estimators=300,
    max_samples=1024,
    contamination=0.01,   # assume ~1% of real traffic is anomalous
    random_state=42,
    n_jobs=-1,
)
iso.fit(X_train_normal_scaled)

# ─────────────────────────────────────────────────────────────────────────────
# Hybrid decision function
# ─────────────────────────────────────────────────────────────────────────────

def normalize_if_score(raw_scores):
    """
    IsolationForest raw scores are negative (more negative = more anomalous).
    Convert to 0–1 where 1 = most anomalous.
    """
    clipped = np.clip(raw_scores, -0.5, 0.5)
    return (clipped - clipped.min()) / (clipped.max() - clipped.min() + 1e-9)

def hybrid_predict(X_scaled, threshold_rf=RF_THRESHOLD,
                   threshold_if=IF_THRESHOLD, rf_unsure_min=RF_UNSURE_MIN):
    """
    Returns (predictions, rf_probs, if_scores, triggered_by)
    triggered_by: 'rf', 'if', or 'none'
    """
    rf_probs    = rf.predict_proba(X_scaled)[:, 1]
    if_raw      = iso.score_samples(X_scaled)
    if_scores   = normalize_if_score(if_raw)

    rf_alert    = rf_probs  >= threshold_rf
    if_alert    = (if_scores >= threshold_if) & (rf_probs >= rf_unsure_min)

    predictions  = (rf_alert | if_alert).astype(int)
    triggered_by = np.where(rf_alert, 'rf', np.where(if_alert, 'if', 'none'))

    return predictions, rf_probs, if_scores, triggered_by

# ─────────────────────────────────────────────────────────────────────────────
# Evaluate
# ─────────────────────────────────────────────────────────────────────────────

preds, rf_probs, if_scores, triggered = hybrid_predict(X_test_scaled)

print("\n--- Hybrid Model Test Results ---")
print(classification_report(y_test, preds, target_names=['Normal','Attack']))

cm = confusion_matrix(y_test, preds)
tn, fp, fn, tp = cm.ravel()
print(f"True Negatives  (correct normal)   : {tn:,}")
print(f"False Positives (normal → alert)   : {fp:,}")
print(f"False Negatives (missed attacks)   : {fn:,}")
print(f"True Positives  (correct attack)   : {tp:,}")

# How many alerts came from each model
attack_mask = preds == 1
print(f"\nAlerts triggered by RF only : {(triggered[attack_mask]=='rf').sum():,}")
print(f"Alerts triggered by IF only : {(triggered[attack_mask]=='if').sum():,}")

# Feature importance from RF
importances = rf.feature_importances_
print("\n--- Feature Importances (RF) ---")
for feat, imp in sorted(zip(feature_cols, importances), key=lambda x: -x[1]):
    bar = '█' * int(imp * 40)
    print(f"  {feat:16} {bar}  {imp:.3f}")

# ─────────────────────────────────────────────────────────────────────────────
# Save
# ─────────────────────────────────────────────────────────────────────────────

model_bundle = {
    'scaler':        scaler,
    'rf':            rf,
    'iso':           iso,
    'feature_cols':  feature_cols,
    'RF_THRESHOLD':  RF_THRESHOLD,
    'IF_THRESHOLD':  IF_THRESHOLD,
    'RF_UNSURE_MIN': RF_UNSURE_MIN,
}
joblib.dump(model_bundle, "model_hybrid.pkl")
print("\nSaved to model_hybrid.pkl")

# ─────────────────────────────────────────────────────────────────────────────
# Usage example — how to use model_hybrid.pkl in your detector
# ─────────────────────────────────────────────────────────────────────────────

print("""
--- How to use in your detector ---

    bundle = joblib.load("model_hybrid.pkl")
    scaler = bundle['scaler']
    rf     = bundle['rf']
    iso    = bundle['iso']

    # One flow: [frame_len, port, proto, flags, packet_rate, byte_rate, conn_duration, upload_ratio]
    flow = [[1500, 443, 6, 0x10, 40, 60000, 120, 0.03]]
    X_scaled = scaler.transform(flow)

    rf_prob    = rf.predict_proba(X_scaled)[0][1]
    if_raw     = iso.score_samples(X_scaled)[0]
    if_score   = (max(-0.5, min(0.5, if_raw)) + 0.5)  # rough normalise

    rf_alert   = rf_prob  >= bundle['RF_THRESHOLD']
    if_alert   = if_score >= bundle['IF_THRESHOLD'] and rf_prob >= bundle['RF_UNSURE_MIN']

    if rf_alert:
        print(f"ALERT [known attack]  RF={rf_prob:.2f}")
    elif if_alert:
        print(f"ALERT [novel anomaly] IF={if_score:.2f}  RF={rf_prob:.2f}")
    else:
        print("Normal")
""")
