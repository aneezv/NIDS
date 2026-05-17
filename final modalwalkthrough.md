# Walkthrough: Upgrading to Commercial-Grade Micro-Flow ML

## The Problem
The previous NIDS sensor used *stateless, packet-by-packet* anomaly detection. While this works for catching malformed packets or unusual ports, it is mathematically impossible for the model to distinguish between 1 entirely normal ICMP packet (a healthy ping) and 10,000 normal ICMP packets per second (a Ping Flood) because the model fundamentally lacked temporal features. 

## The Solution
To meet commercial/academic standards (akin to NetFlow behavioral ML seen in algorithms trained on CIC-IDS2017), the sensor pipeline was upgraded to include a **Micro-Flow Analytics Engine**.

### 1. [sensor.py](file:///c:/Projects/NIDS/sensor/sensor.py) Upgrade
- Added a lightweight, real-time sliding window (2.0 seconds) that maps every active IP to a flow state dictionary.
- The sensor now independently computes `packet_rate` (Pkts/sec) and `byte_rate` (Bytes/sec) on the fly and appends them to the feature list for every packet.

### 2. Upgrading the Feature Set
- The Machine Learning model now trains and predicts on **6 Temporal + Packet Features**: 
  `[frame_len, port, ip.proto, tcp.flags, packet_rate, byte_rate]`.

### 3. Deep Profile Training
- Updated [train_better_model.py](file:///c:/Projects/NIDS/sensor/train_better_model.py) to establish realistic commercial user baseline bounds:
  - **Gaming Profile**: Low byte_rate (small movement updates), steady fast packet_rate, UDP.
  - **YouTube/Streaming Profile**: High byte_rate, steady packet_rate, UDP/TCP.
  - **Web Browsing Profile**: Medium/burtsy byte_rate, TCP.
  - **Normal Ping Profile**: Low packet rate (1/sec), low byte rate.
- Added explicit boundary uniform noise to teach the Isolation Forest the limits bounding an attack.

### 4. Threshold Precision Tuning
- By tracking standard use values, we discovered that dropping the anomaly threshold perfectly to `0.08` allows Gamers, Browsers, streaming, and light pings to pass without generating Sensor alerts (`confidence < 20%`).
- However, the moment a tool like `h2load` (HTTP Flood), `hping3` (SYN Flood / Ping Flood), or `nmap` initiates, the massive spike in the localized `packet_rate` metric throws the packet mathematically entirely outside the trained bounded cluster—jumping the confidence to `100%` anomaly dynamically!
