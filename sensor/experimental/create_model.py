import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

print("🧪 Generating synthetic 'Pro' dataset (TCP + UDP)...")

# --- 1. TCP DATA (Web Browsing) ---
# Normal Web Traffic: High Ports, Proto 6, Flags ACK/PSH
n_tcp = 10000
tcp_data = {
    'frame.len': np.random.choice([60, 1000, 1500], n_tcp, p=[0.1, 0.4, 0.5]),
    'port': np.random.randint(30000, 65000, n_tcp), # High Ephemeral Ports
    'ip.proto': [6] * n_tcp,
    'tcp.flags': np.random.choice([0x10, 0x18], n_tcp, p=[0.5, 0.5])
}

# --- 2. UDP DATA (YouTube/DNS) ---
# Normal UDP: Port 443 (QUIC/YouTube), 53 (DNS). 
# Proto 17. Flags are ALWAYS 0.
n_udp = 5000
udp_data = {
    'frame.len': np.random.choice([80, 1200, 1350], n_udp, p=[0.2, 0.4, 0.4]), # DNS is small, QUIC is big
    'port': np.random.choice([443, 53, 123] + list(np.random.randint(30000, 65000, 100)), n_udp), 
    'ip.proto': [17] * n_udp,
    'tcp.flags': [0] * n_udp # UDP has no flags
}

# Combine them
df_tcp = pd.DataFrame(tcp_data)
df_udp = pd.DataFrame(udp_data)
df = pd.concat([df_tcp, df_udp], ignore_index=True)

print(f"📊 Training on {len(df)} packets (TCP & UDP)...")

# --- TRAIN ---
# We use a slightly higher contamination because UDP is messy
clf = IsolationForest(n_estimators=100, contamination=0.005, random_state=42)
clf.fit(df)

joblib.dump(clf, "model.pkl")
print("✅ Pro Model saved as 'model.pkl'")
