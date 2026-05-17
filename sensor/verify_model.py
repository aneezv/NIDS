import os
import sys

SENSOR_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SENSOR_DIR)
from detector import AnomalyDetector

detector = AnomalyDetector(os.path.join(SENSOR_DIR, "model_advanced.pkl"), threshold=0.115)

# Feature order: [frame_len, port, proto, flags, packet_rate, byte_rate, distinct_ports]

test_data = [
    # Normal profiles — should score 0% anomaly
    [1500, 443, 6, 0x18, 40, 60000,        1],   # YouTube TCP — one CDN endpoint
    [1500, 443, 17, 0, 100, 150000,        1],   # YouTube UDP QUIC
    [128, 27015, 17, 0, 40, 5120,          1],   # Multi-player game
    [1000, 80, 6, 0x10, 20, 20000,         2],   # Web browsing — port 80 + 443
    [64, 0, 1, 0, 1.5, 96,                 1],   # ICMP ping
    [1500, 27015, 6, 0x10, 30000, 45000000, 1],  # Steam download
    [128, 443, 6, 0x18, 80, 200000,        3],   # Multi-tab browsing — 443, 80, 53

    # Volumetric attacks — should fire alerts via packet/byte rate
    [64, 0, 1, 0, 5000, 320000,            1],   # ICMP ping flood
    [1500, 80, 6, 0x18, 2000, 3000000,     1],   # HTTP flood (h2load)
    [64, 53, 17, 0, 4000, 256000,          1],   # UDP DNS flood, single port
    [40, 80, 6, 0x02, 1000, 40000,         1],   # TCP SYN flood, port 80
    [64, 12345, 17, 0, 8000, 512000,      80],   # UDP flood, randomised ports

    # Port/protocol scans — should fire alerts via distinct_ports
    [40, 6667, 6, 0x02, 50, 2000,         50],   # Fast SYN scan — 50 ports
    [40, 445, 6, 0x02, 10, 400,           30],   # Stealth SYN scan — 30 ports in 5s
    [40, 22, 6, 0x02, 2, 80,              10],   # Slow stealth scan — 10 ports
]

labels = [
    "Normal YouTube (TCP)",
    "Normal YouTube (UDP QUIC)",
    "Normal Gaming (UDP)",
    "Normal Web Browsing",
    "Normal Ping",
    "Steam Game Download",
    "Normal Multi-tab Browse",
    "Ping FLOOD",
    "HTTP FLOOD (h2load)",
    "UDP FLOOD (single port)",
    "TCP SYN FLOOD",
    "UDP FLOOD (randomised)",
    "Fast SYN Scan (50 ports)",
    "Stealth Scan (30 ports)",
    "Slow Stealth Scan (10 ports)",
]

results = detector.predict_batch(test_data)

print("\n--- Flow-Level Model Verification Results ---")
for label, (raw_score, confidence) in zip(labels, results):
    print(f"{label:30} | Raw Score: {raw_score:7.3f} | Confidence (Anomaly %): {confidence:6.2f}")
