import subprocess
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import time
import os
import sys

# --- SETTINGS ---
CAPTURE_INTERFACE = "eth0"  # Ensure this matches your interface (ip a)
PACKET_LIMIT = 2000         # How many packets to learn from
MODEL_FILE = "model.pkl"

def hex_to_int(val):
    """
    Helper Function: Converts '0x0010' (String) to 16 (Integer).
    Also handles standard numbers and empty values.
    """
    try:
        return int(str(val), 0) # The '0' argument tells Python to guess base-10 or base-16
    except:
        return 0

def capture_training_data():
    print(f"📡 Capturing {PACKET_LIMIT} packets for baseline... (Generate normal traffic now!)")
    
    # Updated Tshark command with 'tcp.flags'
    cmd = [
        "tshark", "-i", CAPTURE_INTERFACE,
        "-c", str(PACKET_LIMIT),
        "-T", "fields",
        "-e", "frame.len",        # Feature 1
        "-e", "tcp.dstport",      # Feature 2
        "-e", "ip.proto",         # Feature 3
        "-e", "tcp.flags",        # Feature 4 (The Hex value)
        "-E", "separator=,",
        "-E", "header=y"
    ]
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    
    if not stdout:
        print("❌ Error: Tshark captured no data. Check interface name or sudo permissions.")
        print(stderr)
        return pd.DataFrame()

    # Convert CSV string to DataFrame
    from io import StringIO
    data = StringIO(stdout)
    df = pd.read_csv(data)
    
    # --- CRITICAL FIX: CLEANING DATA ---
    # Fill empty values with 0
    df = df.fillna(0)
    
    # Force convert all feature columns from Hex Strings to Integers
    # We apply the 'hex_to_int' function to every single cell
    for col in ['frame.len', 'tcp.dstport', 'ip.proto', 'tcp.flags']:
        if col in df.columns:
            df[col] = df[col].apply(hex_to_int)

    return df

def train_model(df):
    print(f"🧠 Training Isolation Forest on {len(df)} packets...")
    
    clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    
    # Select the 4 features
    features = df[['frame.len', 'tcp.dstport', 'ip.proto', 'tcp.flags']]
    
    clf.fit(features)
    
    joblib.dump(clf, MODEL_FILE)
    print(f"✅ Model saved to {MODEL_FILE}")
    print("   (You are now ready to run sensor.py)")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("⚠️  Warning: You might need sudo to capture packets.")
        
    df = capture_training_data()
    if not df.empty:
        train_model(df)
