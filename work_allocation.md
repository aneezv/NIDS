# NIDS Project: Detailed Work Allocation (Backend Focus)

**Context**:
-   **UI/External Dashboard**: Owned by **Anees** (User).
-   **Core Backend & Intelligence**: Distributed among **Neha**, **Jisto**, and **Devika**.

The work is split to ensure the backend provides robust APIs and reliable data for Anees's UI.

---

## 📦 Module 1: Sensor Intelligence & ML
**Owner: 👩‍💻 Neha**
**Role**: *The "Analyst"*. Responsible for the accuracy of detection and the reliability of the sensor agent.

### 1.1 Robust Anomaly Detection
-   **Task**: Refactor [AnomalyDetector](file:///c:/Projects/NIDS/sensor/detector.py#4-35) class (in [detector.py](file:///c:/Projects/NIDS/sensor/detector.py)).
-   **Detail**:
    -   Replace the hardcoded `0.10` threshold with a dynamic property `self.threshold` loaded from a config file.
    -   Implement a `get_model_metadata()` method that returns model version, training date, and accuracy metrics (so Anees can display this on the UI).
-   **Deliverable**: A robust Python class that doesn't crash on empty packets.

### 1.2 The "Retrain" Workflow
-   **Task**: Create a Feedback Loop mechanism.
-   **Detail**:
    -   Create a new script `train_feedback.py`.
    -   It should accept a directory of "False Positive" PCAPs (verified by Admin) and "True Attack" PCAPs.
    -   It should re-fit the Isolation Forest and save a versioned model (e.g., `model_v2.pkl`).
    -   Expose a function `hot_reload()` in [sensor.py](file:///c:/Projects/NIDS/sensor/sensor.py) to reload the model without restarting the script.

### 1.3 Sensor Reliability (Heartbeat)
-   **Task**: Implement "Keep-Alive" logic.
-   **Detail**:
    -   Modify [sensor.py](file:///c:/Projects/NIDS/sensor/sensor.py) to start a background thread.
    -   Every 30 seconds, send a lightweight POST to `https://CONTROLLER/heartbeat` with `{ "sensor_id": "...", "status": "OK", "cpu_load": 15% }`.
    -   If the Controller is unreachable, log it locally and queue alerts.

---

## 📦 Module 2: Controller Security & Networking
**Owner: 👨‍💻 Jisto**
**Role**: *The "Gatekeeper"*. Responsible for the API gateway, authentication, and active defense.

### 2.1 API Security Layer
-   **Task**: Secure the Flask Endpoints.
-   **Detail**:
    -   Implement **Mutual TLS (mTLS)** or robust API Key validation.
    -   Create a decorator `@require_auth` applied to ALL routes (`/alert`, `/heartbeat`, `/config`).
    -   Ensure [config.json](file:///c:/Projects/NIDS/controller/config.json) is replaced by `python-dotenv` (.env file) to keep secrets out of source code.

### 2.2 Active Enforcement (Firewall)
-   **Task**: Expand [enforcement.py](file:///c:/Projects/NIDS/controller/enforcement.py) capabilities.
-   **Detail**:
    -   Current script only calls [block_ip.sh](file:///c:/Projects/NIDS/controller/block_ip.sh).
    -   Add support for **Unblocking**: Create `unblock_ip.sh` and a Python wrapper `remove_ban(ip)`.
    -   Add support for **Whitelisting**: Allow dynamic addition of IPs to the whitelist at runtime (in memory + file).

### 2.3 Networking Resilience
-   **Task**: Handle SSL and Concurrency.
-   **Detail**:
    -   Ensure the Flask server runs with a production-ready WSGI server (like Gunicorn) or properly threaded for the demo.
    -   Fix the "SSL Fallback" issue—in production, it should *fail* if SSL is broken, not downgrade to insecure HTTP.

---

## 📦 Module 3: Data Engineering & Forensics
**Owner: 👩‍💻 Devika**
**Role**: *The "Librarian"*. Responsible for persistence, logging, and serving data to Anees's UI.

### 3.1 Database Migration (Persistence)
-   **Task**: Replace [VerificationEngine](file:///c:/Projects/NIDS/controller/verification.py#7-50) dictionaries with SQLite.
-   **Detail**:
    -   Set up `SQLAlchemy` with a clean schema:
        -   `SensorNode`: (id, hostname, last_seen, trust_score, status)
        -   `Alert`: (id, timestamp, source_ip, sensor_id, raw_score, payload_json)
        -   `BlockEvent`: (id, ip, duration, blocked_at, expires_at)
    -   Migrate existing logic to read/write from this DB.

### 3.2 The "Management API" (For Anees)
-   **Task**: Build the APIs that the UI will consume.
-   **Detail**:
    -   **`GET /api/nodes`**: Return list of all sensors and their `last_seen` (from Heartbeat data).
    -   **`GET /api/alerts?limit=50`**: Return the most recent alerts from the DB for the Live Monitor.
    -   **`GET /api/status`**: Summary stats (Total Blocked, Active Threats) for the top cards of the Dashboard.
    -   **`POST /api/action/unban`**: Endpoint for the UI "Unban" button.

### 3.3 Logging & Auditing
-   **Task**: Structured Logging.
-   **Detail**:
    -   Ensure every "Action" (Block, Unblock, Config Change) is logged to `audit.log` with a timestamp and user ID.
    -   Provide an API endpoint `GET /api/logs` so Anees can show a system log in the UI.

---

## Summary of Handoffs

1.  **Neha (Sensor)** sends data to **Jisto (API)**.
2.  **Jisto (API)** validates requests and passes data to **Devika (DB Layer)**.
3.  **Anees (UI)** queries **Devika's APIs** to visualize what's happening and sends commands to **Jisto's endpoints** to take action.
