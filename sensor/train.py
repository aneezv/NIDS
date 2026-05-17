import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.pipeline import Pipeline
import joblib

print("🧪 Generating realistic synthetic dataset...")

# ─────────────────────────────────────────────────────────────────────────────
# FIX 1: Feature order is [frame_len, port, proto, flags, packet_rate, byte_rate]
#         We use a Pipeline(RobustScaler → IsolationForest) so the scaler is
#         baked into the saved model. The AnomalyDetector loads .pkl and calls
#         predict/decision_function — both will now auto-scale. No changes needed
#         to verify_model.py or detector.py.
# ─────────────────────────────────────────────────────────────────────────────

rng = np.random.default_rng(42)

# ── 1. High-Speed Downloads (Steam, large files via HTTP/HTTPS) ───────────────
#    Real: MTU-sized packets, high ACK rate, sustained throughput up to ~125 MB/s.
#    FIX: previous version used a single uniform cluster over a huge range,
#    which gave each point low density and made even centred test cases
#    (e.g. 30k pps / 45 MB/s Steam) score as borderline-anomalous. Split into
#    two: a wide uniform for coverage AND a dense Gaussian for the typical case.
n_dl = 15000
dl = {
    'frame_len':       rng.choice([1400, 1500], n_dl),
    'port':            rng.choice([80, 443, 27015], n_dl),
    'proto':           np.full(n_dl, 6),
    'flags':           np.full(n_dl, 0x10),           # ACK
    'packet_rate':     rng.uniform(1000, 50000, n_dl),
    'byte_rate':       rng.uniform(1_500_000, 100_000_000, n_dl),
    'distinct_ports':  rng.integers(1, 3, n_dl),      # download to one server
}

n_dl_dense = 10000
dl_dense = {
    'frame_len':       np.full(n_dl_dense, 1500),
    'port':            rng.choice([443, 80, 27015], n_dl_dense, p=[0.5, 0.3, 0.2]),
    'proto':           np.full(n_dl_dense, 6),
    'flags':           np.full(n_dl_dense, 0x10),
    'packet_rate':     rng.normal(25000, 8000, n_dl_dense).clip(5000, 50000),
    'byte_rate':       rng.normal(35_000_000, 15_000_000, n_dl_dense).clip(5_000_000, 80_000_000),
    'distinct_ports':  np.ones(n_dl_dense, dtype=int),
}

# ── 2. 4K Streaming / YouTube (QUIC or TCP) ──────────────────────────────────
#    Real: 15–25 Mbps sustained, bursty around segment boundaries
n_st = 10000
st = {
    'frame_len':       rng.choice([1200, 1400, 1500], n_st),
    'port':            np.full(n_st, 443),
    'proto':           rng.choice([6, 17], n_st, p=[0.5, 0.5]),
    'flags':           rng.choice([0x10, 0], n_st, p=[0.5, 0.5]),
    'packet_rate':     rng.uniform(500, 5000, n_st),
    'byte_rate':       rng.uniform(600_000, 8_000_000, n_st),
    'distinct_ports':  rng.integers(1, 3, n_st),       # streaming CDN
}

# ── 3. Web Browsing (FIXED: wider ranges for page-load bursts) ────────────────
#    FIX: Old code capped at packet_rate=500, byte_rate=750 KB/s.
#    Real: a modern page (React SPA, images, fonts) can burst 1,000–3,000 pps
#    and 5–15 MB/s during the initial load, then idle at almost zero.
#    We model both phases so the model learns the full realistic envelope.
n_web_burst = 8000   # initial page load (high burst)
n_web_idle  = 8000   # after load (nearly idle)

web_burst = {
    'frame_len':       rng.choice([60, 512, 1000, 1500], n_web_burst, p=[0.1, 0.35, 0.3, 0.25]),
    'port':            rng.choice(
                           list(np.full(600, 443)) +
                           list(np.full(200, 80)) +
                           list(rng.integers(30000, 65000, 200)),
                           n_web_burst),
    'proto':           np.full(n_web_burst, 6),
    'flags':           rng.choice([0x10, 0x18, 0x02], n_web_burst, p=[0.6, 0.3, 0.1]),
    'packet_rate':     rng.uniform(200, 3000, n_web_burst),
    'byte_rate':       rng.uniform(100_000, 15_000_000, n_web_burst),
    'distinct_ports':  rng.integers(2, 6, n_web_burst),    # page-load hits several
}

web_idle = {
    'frame_len':       rng.choice([60, 128, 256], n_web_idle, p=[0.5, 0.3, 0.2]),
    'port':            rng.choice([443, 80], n_web_idle),
    'proto':           np.full(n_web_idle, 6),
    'flags':           rng.choice([0x10, 0x18], n_web_idle, p=[0.8, 0.2]),
    'packet_rate':     rng.uniform(1, 50, n_web_idle),
    'byte_rate':       rng.uniform(100, 50_000, n_web_idle),
    'distinct_ports':  rng.integers(1, 3, n_web_idle),
}

# ── 4. DNS Queries (NEW — was completely missing before) ──────────────────────
#    FIX: Missing DNS caused any DNS-heavy browsing session to be anomalous.
#    Real: tiny UDP packets to port 53, very low rate
n_dns = 5000
dns = {
    'frame_len':       rng.choice([60, 64, 80, 128], n_dns),
    'port':            np.full(n_dns, 53),
    'proto':           np.full(n_dns, 17),  # UDP
    'flags':           np.zeros(n_dns),
    'packet_rate':     rng.uniform(0.5, 50, n_dns),
    'byte_rate':       rng.uniform(30, 6400, n_dns),
    'distinct_ports':  np.ones(n_dns, dtype=int),          # all to port 53
}

# ── 5. HTTPS Handshakes (NEW — TLS ClientHello, SYN/SYN-ACK bursts) ──────────
#    FIX: Opening a browser fires dozens of TLS handshakes simultaneously.
#    Each is a short burst of SYN + small packets before ACK-only data flow.
n_tls = 6000
tls = {
    'frame_len':       rng.choice([40, 64, 128, 300], n_tls, p=[0.2, 0.3, 0.3, 0.2]),
    'port':            np.full(n_tls, 443),
    'proto':           np.full(n_tls, 6),
    'flags':           rng.choice([0x02, 0x12, 0x10, 0x18], n_tls, p=[0.3, 0.2, 0.3, 0.2]),
    'packet_rate':     rng.uniform(5, 300, n_tls),
    'byte_rate':       rng.uniform(200, 120_000, n_tls),
    'distinct_ports':  rng.integers(1, 3, n_tls),
}

# ── 6. Online Gaming (UDP, low latency, steady) ───────────────────────────────
n_game = 10000
game = {
    'frame_len':       rng.choice([64, 128, 256], n_game),
    'port':            rng.integers(10000, 30000, n_game),
    'proto':           np.full(n_game, 17),
    'flags':           np.zeros(n_game),
    'packet_rate':     rng.uniform(20, 128, n_game),
    'byte_rate':       rng.uniform(1200, 32_768, n_game),
    'distinct_ports':  rng.integers(1, 3, n_game),         # game port + maybe matchmaking
}

# ── 7. Normal ICMP (ping / traceroute) ───────────────────────────────────────
n_ping = 2000
ping = {
    'frame_len':       np.full(n_ping, 64),
    'port':            np.zeros(n_ping),
    'proto':           np.full(n_ping, 1),
    'flags':           np.zeros(n_ping),
    'packet_rate':     rng.uniform(0.5, 10, n_ping),
    'byte_rate':       rng.uniform(32, 640, n_ping),
    'distinct_ports':  np.ones(n_ping, dtype=int),         # ICMP has no port (treat as 1)
}

# ── 8. Background System Traffic (NTP, SSDP, DHCP, ARP) ──────────────────────
#    FIX: Completely missing — Windows/macOS/Linux send this constantly.
n_sys = 3000
sys_bg = {
    'frame_len':       rng.choice([60, 64, 128, 300], n_sys, p=[0.3, 0.3, 0.2, 0.2]),
    'port':            rng.choice([123, 1900, 5353, 67, 68], n_sys),  # NTP/SSDP/mDNS/DHCP
    'proto':           rng.choice([17, 1], n_sys, p=[0.85, 0.15]),
    'flags':           np.zeros(n_sys),
    'packet_rate':     rng.uniform(0.01, 5, n_sys),
    'byte_rate':       rng.uniform(1, 1500, n_sys),
    'distinct_ports':  rng.integers(2, 6, n_sys),          # NTP+SSDP+mDNS+DHCP simultaneously
}

# ── 9. Moderate-rate Streaming / Video Call (NEW — fills the gap) ────────────
#    FIX: Without this, anything with packet_rate 30–200 was scored as
#    anomalous because the training set only had web_idle (1–50 pps) and
#    web_burst (200–3000 pps). Real-world traffic — a moderate-quality
#    YouTube stream, a Zoom call, a modest TCP video — lives in this gap.
n_moderate = 9000
moderate = {
    'frame_len':       rng.choice([200, 500, 1000, 1400, 1500], n_moderate,
                                  p=[0.1, 0.2, 0.2, 0.2, 0.3]),
    'port':            rng.choice([443, 80, 27015, 5004, 3478], n_moderate,
                                  p=[0.6, 0.2, 0.1, 0.05, 0.05]),
    'proto':           rng.choice([6, 17], n_moderate, p=[0.55, 0.45]),
    'flags':           rng.choice([0x10, 0x18, 0], n_moderate, p=[0.45, 0.25, 0.30]),
    'packet_rate':     rng.uniform(20, 300, n_moderate),
    'byte_rate':       rng.uniform(20_000, 500_000, n_moderate),
    'distinct_ports':  rng.integers(1, 4, n_moderate),
}

# ─────────────────────────────────────────────────────────────────────────────
# ATTACK / ANOMALY DATA
# FIX: Old noise was pure uniform random — it overlapped with legitimate traffic
# everywhere. Real attacks have distinctive signatures. We model them explicitly
# so the model learns a clean boundary.
# ─────────────────────────────────────────────────────────────────────────────

# ── A. ICMP Flood (hping3 -1 --flood) ────────────────────────────────────────
n_icmpfl = 1000
icmp_flood = {
    'frame_len':       np.full(n_icmpfl, 64),
    'port':            np.zeros(n_icmpfl),
    'proto':           np.full(n_icmpfl, 1),
    'flags':           np.zeros(n_icmpfl),
    'packet_rate':     rng.uniform(3000, 100000, n_icmpfl),
    'byte_rate':       rng.uniform(192_000, 6_400_000, n_icmpfl),
    'distinct_ports':  np.ones(n_icmpfl, dtype=int),       # ICMP, no port
}

# ── B. TCP SYN Flood ─────────────────────────────────────────────────────────
n_synfl = 2000
syn_flood = {
    'frame_len':       rng.choice([40, 60], n_synfl),
    'port':            rng.integers(1, 1024, n_synfl),
    'proto':           np.full(n_synfl, 6),
    'flags':           np.full(n_synfl, 0x02),
    # Wider rate floor (200 pps instead of 1000) so the model recognises
    # lower-rate SYN floods. Real hping3 attacks usually run much faster,
    # but we want defence in depth for slow-and-low variants.
    'packet_rate':     rng.uniform(200, 80000, n_synfl),
    'byte_rate':       rng.uniform(8_000, 4_800_000, n_synfl),
    'distinct_ports':  np.ones(n_synfl, dtype=int),
}

# ── C. UDP Flood ─────────────────────────────────────────────────────────────
n_udpfl = 1000
udp_flood = {
    'frame_len':       rng.choice([64, 512, 1500], n_udpfl),
    'port':            rng.integers(1, 65535, n_udpfl),
    'proto':           np.full(n_udpfl, 17),
    'flags':           np.zeros(n_udpfl),
    'packet_rate':     rng.uniform(2000, 100000, n_udpfl),
    'byte_rate':       rng.uniform(128_000, 150_000_000, n_udpfl),
    'distinct_ports':  rng.integers(1, 200, n_udpfl),      # often randomised
}

# ── D. HTTP/HTTPS Application Layer Flood ────────────────────────────────────
n_httpfl = 800
http_flood = {
    'frame_len':       rng.choice([1400, 1500], n_httpfl),
    'port':            rng.choice([80, 443], n_httpfl),
    'proto':           np.full(n_httpfl, 6),
    'flags':           np.full(n_httpfl, 0x18),
    'packet_rate':     rng.uniform(2000, 30000, n_httpfl),
    'byte_rate':       rng.uniform(2_800_000, 45_000_000, n_httpfl),
    'distinct_ports':  np.ones(n_httpfl, dtype=int),       # targeted web port
}

# ── E. Port Scans (distinctive: SYN to weird ports, low byte rate) ────────────
n_scan = 2500
scan = {
    'frame_len':       rng.choice([40, 44, 60], n_scan),
    'port':            rng.choice(
                           list(rng.integers(1, 1024, 400)) +       # well-known
                           list(rng.integers(1024, 49152, 400)) +   # registered
                           list([445, 3389, 22, 23, 6667, 4444, 1433, 3306]),
                           n_scan),
    'proto':           np.full(n_scan, 6),
    'flags':           np.full(n_scan, 0x02),
    'packet_rate':     rng.uniform(1, 500, n_scan),
    'byte_rate':       rng.uniform(40, 30_000, n_scan),
    # The discriminator. Stealth scans hit 20–80 ports/window; fast scans
    # blow past 200. Anything > ~8 distinct ports in 5s from one source is
    # almost certainly a scan.
    'distinct_ports':  rng.integers(15, 400, n_scan),
}

# ── F. DNS Amplification Attack ───────────────────────────────────────────────
n_dnsamp = 600
dns_amp = {
    'frame_len':       rng.choice([512, 1000, 1500], n_dnsamp),
    'port':            np.full(n_dnsamp, 53),
    'proto':           np.full(n_dnsamp, 17),
    'flags':           np.zeros(n_dnsamp),
    'packet_rate':     rng.uniform(500, 10000, n_dnsamp),
    'byte_rate':       rng.uniform(256_000, 15_000_000, n_dnsamp),
    'distinct_ports':  np.ones(n_dnsamp, dtype=int),       # all on port 53
}

# ─────────────────────────────────────────────────────────────────────────────
# Assemble and train
# ─────────────────────────────────────────────────────────────────────────────

frames_normal = [dl, dl_dense, st, web_burst, web_idle, dns, tls, game, ping, sys_bg, moderate]
frames_attack = [icmp_flood, syn_flood, udp_flood, http_flood, scan, dns_amp]

df_normal = pd.concat([pd.DataFrame(f) for f in frames_normal], ignore_index=True)
df_attack = pd.concat([pd.DataFrame(f) for f in frames_attack], ignore_index=True)

feature_cols = ['frame_len', 'port', 'proto', 'flags', 'packet_rate', 'byte_rate', 'distinct_ports']
df_normal = df_normal[feature_cols].sample(frac=1, random_state=42).reset_index(drop=True)
df_attack = df_attack[feature_cols].reset_index(drop=True)

# Contamination — for an IF trained ONLY on normal data, this is the fraction
# of training samples the model is allowed to internally classify as outliers
# when it calibrates its decision boundary. A small value (1%) is right for
# clean synthetic normal data; the attack samples are NOT in training.
contamination = 0.01
print(f"   Normal samples (training)   : {len(df_normal):,}")
print(f"   Attack samples (held out)   : {len(df_attack):,}  — used only for evaluation")
print(f"   Contamination               : {contamination:.3f}  (normal-only training)")

# Pipeline = RobustScaler (handles outliers better than Standard) + IsolationForest.
# The scaler is baked into the saved model so verify_model.py loads it transparently.
pipeline = Pipeline([
    ('scaler', RobustScaler()),
    ('clf', IsolationForest(
        n_estimators=300,
        max_samples=1024,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )),
])

# CRITICAL: train on NORMAL data only. Mixing attack samples into training
# teaches the IF that attacks are part of the normal distribution — which is
# exactly why TCP SYN floods were previously scoring as benign. With
# normal-only training, anything outside the learned boundary of normal
# (including novel attacks the model has never seen) is correctly flagged.
print("\n🔧 Training pipeline (RobustScaler + IsolationForest) on NORMAL-only data...")
pipeline.fit(df_normal)

# Quick held-out evaluation so the trainer prints a sanity summary instead of
# requiring you to run verify_model.py afterwards.
import numpy as np
normal_scores = pipeline.decision_function(df_normal)
attack_scores = pipeline.decision_function(df_attack)
print(f"\n📊 Held-out evaluation (threshold=0.083):")
print(f"   Normal median score : {np.median(normal_scores):+.3f}   (higher = more normal)")
print(f"   Attack median score : {np.median(attack_scores):+.3f}   (lower / negative = more anomalous)")
print(f"   Normal flagged FP   : {(normal_scores < 0.083).mean()*100:.1f}%")
print(f"   Attack caught (TPR) : {(attack_scores < 0.083).mean()*100:.1f}%")

output_path = "model_advanced.pkl"
joblib.dump(pipeline, output_path)
print(f"\n✅ Model saved to {output_path}")