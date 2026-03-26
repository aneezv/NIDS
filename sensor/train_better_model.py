import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

print("🧪 Generating synthetic dataset for high-speed clients (Gigabit Downloads, 4K Video)...")

# 1. High-Speed Downloads (Steam, Large Files)
# Up to 50k pkts/sec, MTU size packets (1500), mostly ACK (0x10) flags
n_dl = 15000
dl_data = {
    'frame.len': np.random.choice([1400, 1500], n_dl),
    'port': np.random.choice([80, 443, 27015], n_dl), # HTTP, HTTPS, Steam
    'ip.proto': [6] * n_dl,
    'tcp.flags': [0x10] * n_dl, # ACK
    'packet_rate': np.random.uniform(1000, 50000, n_dl),
    'byte_rate': np.random.uniform(1500000, 75000000, n_dl) # Up to 75 MB/s
}

# 2. 4K Streaming / YouTube (QUIC UDP or TCP)
n_stream = 10000
stream_data = {
    'frame.len': np.random.choice([1200, 1400, 1500], n_stream),
    'port': [443] * n_stream,
    'ip.proto': np.random.choice([6, 17], n_stream, p=[0.5, 0.5]),
    'tcp.flags': np.random.choice([0x10, 0], n_stream, p=[0.5, 0.5]),
    'packet_rate': np.random.uniform(500, 5000, n_stream),
    'byte_rate': np.random.uniform(600000, 7500000, n_stream) # Up to 7.5 MB/s
}

# 3. Gaming (Low latency UDP, steady packet rate, very low byte rate)
n_game = 10000
game_data = {
    'frame.len': np.random.choice([64, 128, 256], n_game),
    'port': np.random.randint(10000, 30000, n_game),
    'ip.proto': [17] * n_game,
    'tcp.flags': [0] * n_game,
    'packet_rate': np.random.uniform(20, 100, n_game),
    'byte_rate': np.random.uniform(1200, 25000, n_game)
}

# 4. Standard Web Browsing (Bursty TCP traffic, high ports, mixed sizes)
n_web = 10000
web_data = {
    'frame.len': np.random.choice([60, 512, 1000, 1500], n_web, p=[0.1, 0.4, 0.3, 0.2]),
    'port': np.random.choice([443, 80] + list(np.random.randint(30000, 65000, 1000)), n_web),
    'ip.proto': [6] * n_web,
    'tcp.flags': np.random.choice([0x10, 0x18], n_web, p=[0.7, 0.3]),
    'packet_rate': np.random.uniform(5, 500, n_web),
    'byte_rate': np.random.uniform(300, 750000, n_web)
}

# 5. Standard ICMP (Ping)
n_ping = 2000
ping_data = {
    'frame.len': [64] * n_ping,
    'port': [0] * n_ping,
    'ip.proto': [1] * n_ping,
    'tcp.flags': [0] * n_ping,
    'packet_rate': np.random.uniform(0.5, 5, n_ping),
    'byte_rate': np.random.uniform(32, 320, n_ping)
}

# 6. Volumetric Noise Bounds
n_noise = 2500
noise_data = {
    'frame.len': np.random.randint(0, 2000, n_noise),
    'port': np.random.randint(0, 65535, n_noise),
    'ip.proto': np.random.randint(0, 255, n_noise),
    'tcp.flags': np.random.randint(0, 255, n_noise),
    'packet_rate': np.random.uniform(0, 100000, n_noise), 
    'byte_rate': np.random.uniform(0, 150000000, n_noise) 
}

df_dl = pd.DataFrame(dl_data)
df_stream = pd.DataFrame(stream_data)
df_game = pd.DataFrame(game_data)
df_web = pd.DataFrame(web_data)
df_ping = pd.DataFrame(ping_data)
df_noise = pd.DataFrame(noise_data)

df = pd.concat([df_dl, df_stream, df_game, df_web, df_ping, df_noise], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

clf = IsolationForest(
    n_estimators=200, 
    max_samples=1000, 
    contamination=len(df_noise)/len(df),
    random_state=42, 
    n_jobs=-1
)

clf.fit(df)
joblib.dump(clf, "model_advanced.pkl")
print("✅ High-Speed Commercial NetFlow Model saved!")
