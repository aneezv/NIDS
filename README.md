# Network Immune Defense System (NIDS)

**A Verification-Based Network Defense System**

NIDS (Network Immune Defense System) is a novel security framework that separates anomaly detection from enforcement. It uses machine learning to identify potential threats but relies on a robust verification layer to prevent false positives from disrupting legitimate traffic.

> **Core Philosophy**: "ML is a signal, not an authority."

## 🎯 Core Problem
Traditional Anomaly-based IDS systems detect unknown attacks but often suffer from high false positive rates. Automatically blocking traffic based solely on ML output is risky and can lead to self-inflicted Denial of Service (DoS). NIDS solves this by introducing a **Verification Layer** that aggregates evidence before taking action.

## 🧬 Architecture

`[ Live Network Traffic ]` → `[ IDS Sensor ]` → `[ Verification Controller ]` → `[ Router Enforcement ]`

### 1️⃣ IDS Sensor (The "Analyst")
*   Captures live network traffic.
*   Uses **Isolation Forest** (Unsupervised ML) to detect statistical anomalies.
*   **Never blocks traffic** directly.
*   Sends alerts to the Controller.

### 2️⃣ Controller (The "Gatekeeper")
*   Serves as the central brain and Verification Layer.
*   Aggregates alerts from multiple sensors.
*   Computes a **Confidence Score** based on:
    *   Frequency of anomalies.
    *   Multi-sensor corroboration.
    *   Source IP reputation/history.
    *   Sensor trust levels.
*   Only triggers enforcement if confidence exceeds a strict threshold.

### 3️⃣ Enforcement (The "Bouncer")
*   Implemented at the router level (using `ipset` + `iptables`).
*   Blocks are **time-limited** and **reversible**.
*   Ensures minimal disruption to legitimate users.

## 📂 Project Structure

```
NIDS/
├── controller/       # The central verification server (Flask)
│   ├── config.json   # Controller configuration
│   ├── enforcement.py# Logic for blocking/unblocking IPs
│   ├── requirements.txt
│   └── ...
├── sensor/           # The distributed monitoring agent
│   ├── detector.py   # Anomaly detection logic (Isolation Forest)
│   ├── sensor.py     # Main agent script
│   ├── requirements.txt
│   └── ...
├── attacker/         # Tools for simulating attacks (for testing)
└── ...
```

## 🚀 Getting Started

### Prerequisites
*   Python 3.10+
*   Linux on the sensor and router VMs (tshark, ipset, iptables)
*   Root/sudo on the sensor (for packet capture) and the router (for ipset/iptables)

### 1. Setup the Controller

```bash
cd controller
pip install -r requirements.txt

# Set the shared API key — the same value also goes in sensor/.env
echo "API_KEY=<your-secret-key>" > .env

# Initialise / migrate the SQLite database (idempotent — safe to re-run)
python setup_db.py

# Start the controller
python app.py
```

The dashboard is served at `http://<controller-host>:5000/dashboard`. The API key
is injected into the page from `.env` — it is never hardcoded in the JS bundle.

### 2. Train the model (one-time)

```bash
cd sensor
pip install -r requirements.txt
python train.py             # writes model_advanced.pkl
python verify_model.py      # sanity-check the model on canned inputs
```

`train.py` is the only canonical trainer. The alternative trainers in
`sensor/experimental/` are kept for reference only — see that folder's README.

### 3. Setup a Sensor

```bash
cd sensor

# Same API key as the controller
echo "API_KEY=<your-secret-key>" > .env

# Edit config.json:
#   - controller_url        : URL of your controller's /alert endpoint
#   - interface             : NIC to sniff (e.g. eth0)
#   - sensor_id             : unique name per sensor node
#   - cert_path             : path to the controller's TLS cert, if using HTTPS
sudo python sensor.py
```

### 4. (Optional) Run an attack rehearsal

```bash
cd attacker
./prepare_attack.sh         # adjust ROUTER_IP at the top first
# then run hping3 / nmap from this host
```

Watch the dashboard: the sensor sends alerts → the controller computes a
verification score → if confidence exceeds the threshold the router blocks
the IP via ipset, time-limited and reversible.

## 👥 Contributors

*   **Anees**: UI Design & Dashboard Integration
*   **Neha**: Sensor Intelligence & Anomaly Detection
*   **Jisto**: API Security & Enforcement Framework
*   **Devika**: Data Persistence & Management APIs

---
*Built for the Advanced Network Security Project.*
