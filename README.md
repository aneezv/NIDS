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
*   Python 3.8+
*   Admin/Root privileges (for packet capture and iptables)

### 1. Setup the Controller
The Controller manages alerts and enforcement.

```bash
cd controller
pip install -r requirements.txt
# Configure environment variables if needed
python controller.py
```

### 2. Setup a Sensor
Sensors run on network nodes to monitor traffic.

```bash
cd sensor
pip install -r requirements.txt
# Edit config.json to point to your Controller IP
python sensor.py
```

## 👥 Contributors

*   **Anees**: UI Design & Dashboard Integration
*   **Neha**: Sensor Intelligence & Anomaly Detection
*   **Jisto**: API Security & Enforcement Framework
*   **Devika**: Data Persistence & Management APIs

---
*Built for the Advanced Network Security Project.*
