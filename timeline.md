# NIDS Integration Timeline

This timeline synchronizes the backend agents (Neha, Jisto, Devika) with your (Anees) UI development.

## 📅 Phase 1: Foundation & Security (Days 1-3)
**Goal**: *Secure the channels and prepare the database. No more data loss.*

| Owner | Task | Dependency |
| :--- | :--- | :--- |
| **Jisto** | **Secure API Gateway**: Implement `@require_auth` and Env Vars. | None |
| **Devika**| **DB Migration**: Setup SQLite/SQLAlchemy schema (`Sensors`, `Alerts`). | Jisto (for context) |
| **Neha** | **Sensor Cleanup**: Refactor [sensor.py](file:///c:/Projects/NIDS/sensor/sensor.py) to use config files (remove hardcoded vals). | None |
| **Anees** | **UI Mockups**: Design the Dashboard layout (HTML/CSS) with mock data. | None |

> **Milestone 1**: The Controller starts up with a Database. Sensors must authenticate to send alerts.

---

## 📅 Phase 2: Core Logic & APIs (Days 4-7)
**Goal**: *Make it robust. Enable communication between Frontend and Backend.*

| Owner | Task | Dependency |
| :--- | :--- | :--- |
| **Devika**| **Management APIs**: Build `GET /api/alerts` and `GET /api/nodes`. | Phase 1 DB |
| **Neha** | **Sensor Reliability**: Implement Heartbeats (ping every 30s) & Retry Queue. | Phase 1 Auth |
| **Jisto** | **Enforcement**: Build `unblock_ip.sh` and the wrapper logic. | None |
| **Anees** | **UI Integration**: Connect Dashboard to Devika's `GET` APIs. | Devika's APIs |

> **Milestone 2**: You can see "Live" sensors on your Dashboard. If you kill a sensor, it shows as "Offline" after 60s.

---

## 📅 Phase 3: Intelligence & Active Defense (Days 8-10)
**Goal**: *Close the loop. Retraining and Manual Actions.*

| Owner | Task | Dependency |
| :--- | :--- | :--- |
| **Neha** | **Feedback Loop**: Create `train_feedback.py` to update the model. | Phase 2 |
| **Devika**| **Action APIs**: Build `POST /api/action/unban` endpoint. | Jisto's Enforcement |
| **Jisto** | **Production Ready**: Setup Gunicorn/SSL (No fallback). | All |
| **Anees** | **Command Center**: Wire "Unban" button to Devika's Action API. | Devika's Action API |

> **Milestone 3**: Full End-to-End Demo. Attack → Detect → Alert (UI) → Block → Admin Unblocks (UI).
