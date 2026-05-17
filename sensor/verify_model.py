import os
import sys

SENSOR_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SENSOR_DIR)
from detector import AnomalyDetector

detector = AnomalyDetector(os.path.join(SENSOR_DIR, "model_advanced.pkl"), threshold=0.083)

# [frame_len, port, proto, flags, packet_rate, byte_rate]

test_data = [
    # Normal Commercial / Gamer Profiles (Should be 0% anomaly)
    [1500, 443, 6, 0x18, 40, 60000],       # Normal YouTube Streaming (tcp)
    [1500, 443, 17, 0, 100, 150000],       # Normal YouTube QUIC (udp)
    [128, 27015, 17, 0, 40, 5120],         # Normal Multi-player Game UDP
    [1000, 80, 6, 0x10, 20, 20000],        # Normal Web Browsing
    [64, 0, 1, 0, 1.5, 96],                # Normal ICMP Ping (1.5 pings/sec)
    [1500, 27015, 6, 0x10, 30000, 45000000], # [NEW] 45 MB/s Steam Game Download!
    
    # Volumetric Attacks
    [64, 0, 1, 0, 5000, 320000],           # ICMP Ping Flood (hping3 -1 --flood)
    [1500, 80, 6, 0x18, 2000, 3000000],    # HTTP Flood / h2load benchmarking
    [64, 53, 17, 0, 4000, 256000],         # UDP DNS Flood 
    [40, 80, 6, 0x02, 1000, 40000],        # TCP SYN Flood (hping3 -S --flood)
    
    # Port/Protocol Scans (weird ports regardless of rate)
    [40, 6667, 6, 0x02, 10, 400],          # SYN Scan to Botnet port
    [40, 445, 6, 0x02, 2, 80]              # Slow SYN Scan to SMB port
]

labels = [
    "Normal YouTube (TCP)",
    "Normal YouTube (UDP QUIC)",
    "Normal Gaming (UDP)",
    "Normal Web Browsing",
    "Normal Ping",
    "Steam Game Download",
    "Ping FLOOD",
    "HTTP FLOOD (h2load)",
    "UDP FLOOD",
    "TCP SYN FLOOD",
    "SYN Scan (Botnet Port)",
    "Slow SYN Scan (SMB)"
]

results = detector.predict_batch(test_data)

print("\n--- Flow-Level Model Verification Results ---")
for label, (raw_score, confidence) in zip(labels, results):
    print(f"{label:30} | Raw Score: {raw_score:7.3f} | Confidence (Anomaly %): {confidence:6.2f}")
