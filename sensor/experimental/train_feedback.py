import argparse
import os
import glob
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

# ---- Feature columns must match detector.py exactly ----
FEATURE_COLS = ['frame.len', 'port', 'ip.proto', 'tcp.flags']

def hex_to_int(val):
    """Same helper as train.py — handles hex strings like '0x0010'."""
    try:
        return int(str(val), 0)
    except:
        return 0

def load_csvs_from_dir(directory):
    """Load and concatenate all CSV files in a directory."""
    csv_files = glob.glob(os.path.join(directory, "*.csv"))
    if not csv_files:
        print(f"⚠️  No CSV files found in: {directory}")
        return pd.DataFrame()

    dfs = []
    for f in csv_files:
        try:
            df = pd.read_csv(f)
            dfs.append(df)
            print(f"   📄 Loaded: {os.path.basename(f)} ({len(df)} rows)")
        except Exception as e:
            print(f"   ❌ Failed to load {f}: {e}")

    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def prepare_features(df):
    """Clean and extract the 4 features that detector.py expects."""
    df = df.fillna(0)

    # Convert hex strings to integers
    for col in ['frame.len', 'tcp.dstport', 'udp.dstport', 'ip.proto', 'tcp.flags']:
        if col in df.columns:
            df[col] = df[col].apply(hex_to_int)

    # Combine TCP + UDP ports into single 'port' column (matches train.py logic)
    if 'udp.dstport' in df.columns and 'tcp.dstport' in df.columns:
        df['port'] = df['tcp.dstport'] + df['udp.dstport']
    elif 'tcp.dstport' in df.columns:
        df['port'] = df['tcp.dstport']
    else:
        df['port'] = 0

    # Keep only the 4 required feature columns
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"❌ Missing columns in data: {missing}")
        return pd.DataFrame()

    return df[FEATURE_COLS]

def get_next_version(model_dir="."):
    """Find the next version number for the model file."""
    existing = glob.glob(os.path.join(model_dir, "model_v*.pkl"))
    versions = []
    for f in existing:
        try:
            v = int(os.path.basename(f).replace("model_v", "").replace(".pkl", ""))
            versions.append(v)
        except:
            pass
    return max(versions, default=1) + 1

def train_model(features_df, output_path, contamination=0.05):
    """Train the Isolation Forest and save the model."""
    print(f"\n🧠 Training Isolation Forest on {len(features_df)} samples...")
    print(f"   Contamination (attack ratio): {contamination}")

    clf = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42
    )
    clf.fit(features_df)
    joblib.dump(clf, output_path)
    print(f"✅ Model saved to: {output_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Retrain NIDS Isolation Forest on new feedback data."
    )
    parser.add_argument(
        "--benign-dir",
        required=True,
        help="Directory containing CSV files of BENIGN (normal) traffic."
    )
    parser.add_argument(
        "--attack-dir",
        required=True,
        help="Directory containing CSV files of ATTACK traffic."
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Fraction of attack samples in combined data (default: 0.05). "
             "Set this to roughly attack_samples / total_samples."
    )
    args = parser.parse_args()

    print("📂 Loading BENIGN data...")
    benign_df = load_csvs_from_dir(args.benign_dir)

    print("📂 Loading ATTACK data...")
    attack_df = load_csvs_from_dir(args.attack_dir)

    if benign_df.empty and attack_df.empty:
        print("❌ No data loaded. Exiting.")
        return

    # Combine both datasets
    combined = pd.concat([benign_df, attack_df], ignore_index=True)
    print(f"\n📊 Combined dataset: {len(combined)} rows "
          f"({len(benign_df)} benign + {len(attack_df)} attack)")

    # Prepare features
    features = prepare_features(combined)
    if features.empty:
        print("❌ Feature extraction failed. Exiting.")
        return

    # Print basic metrics
    n_samples = len(features)
    contamination = args.contamination
    print(f"\n📈 Metrics:")
    print(f"   n_samples     : {n_samples}")
    print(f"   contamination : {contamination}")
    print(f"   features      : {FEATURE_COLS}")

    # Determine output path
    version = get_next_version()
    output_path = f"model_v{version}.pkl"

    train_model(features, output_path, contamination)
    print(f"\n🎉 Done! Use this model by updating config.json → model_path: \"{output_path}\"")

if __name__ == "__main__":
    main()
