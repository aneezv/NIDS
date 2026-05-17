# NIDS Project – Updated Timeline with Explicit Ownership

This timeline defines the execution order of tasks for the Network Immune Defense System (NIDS).
Each task explicitly lists the **responsible team member** to ensure accountability and clarity.
Tasks marked (BLOCKER) must be completed before dependent tasks can proceed.

**type x in between - [ ] to check mark your work completetion ( -[x] )**

---

## Phase 0: Environment & Repository Setup (Week 0)
(Foundational – BLOCKER for all development)

**Owner: Jisto**

- [x] Finalize project folder structure (sensor / controller / ui)
- [x] Setup Git repository and branching strategy
- [x] Define configuration format (.env, config files)
- [ ] Define alert & heartbeat JSON schema

---

## Phase 1: Sensor Stability & Communication (Week 1)
(BLOCKER for Controller & Verification)

### Sensor Core & ML
**Owner: Neha**
- [x] Refactor `AnomalyDetector` to use configurable threshold
- [x] Ensure detector handles empty or malformed packets safely
- [x] Implement `get_model_metadata()` (version, training date, metrics)

### Sensor Reliability
**Owner: Neha**
- [x] Implement heartbeat thread (every 30s)
- [x] Queue alerts locally if controller is unreachable
- [x] Attach `sensor_id` to all outgoing messages

---

## Phase 2: Secure Controller API & Data Flow (Week 2)
(BLOCKER for Persistence, Trust & UI)

### API Security & Networking
**Owner: Jisto**
- [x] Implement API authentication (API keys or mTLS)
- [x] Move secrets from config files to `.env`
- [x] Enforce SSL-only communication (no HTTP fallback)
- [x] Validate all incoming sensor payloads

### Core Controller Endpoints
**Owner: Jisto**
- [x] POST `/alert`
- [x] POST `/heartbeat`
- [x] POST `/config` (admin-only)

---

## Phase 3: Persistence & Trust Infrastructure (Week 3)
(BLOCKER for Verification Logic)

### Database & Models
**Owner: Devika**
- [x] Setup SQLite with SQLAlchemy
- [x] Implement DB schema:
  - SensorNode (id, trust_score, last_seen, status)
  - Alert (id, timestamp, source_ip, sensor_id, raw_score)
  - BlockEvent (id, ip, blocked_at, expires_at)

### Trust Management
**Owner: Devika**
- [x] Initialize trust score for new sensors
- [x] Update trust score based on verification outcomes
- [x] Persist trust changes in database

---

## Phase 4: Verification Engine (Week 4)
(CORE SYSTEM LOGIC)

### Verification Rules
**Owner: Jisto (Logic) + Devika (Data Access)**
- [x] Correlate alerts from multiple sensors
- [x] Fetch trust score of alerting sensor
- [x] Evaluate runtime IP behavior history        _(partial: 1-hour cumulative window only)_
- [x] Compute verification confidence score        _(not implemented as named value)_

### Trust-Aware Decision Logic
**Owner: Jisto**
- [x] High-trust sensor → fewer verification steps
- [x] Low-trust sensor → require stronger evidence
- [x] Borderline confidence → enqueue IP for honeypot via `HoneypotQueue` table

### Verdict Visibility
**Owner: Jisto**
- [x] `process_threat()` returns structured dict: `{ ip, score, confidence, verdict, sensor_trust, sensors }`
- [x] Every verdict persisted to `VerificationResult` DB table
- [x] `GET /api/verdicts` endpoint exposes verdicts to dashboard
- [x] `GET /api/honeypot` endpoint exposes unprocessed BORDERLINE queue

---

## Phase 5: Enforcement & Reversibility (Week 5)
(BLOCKER for Demo)

### Firewall & Response
**Owner: Jisto**
- [x] Implement `block_ip()` at router level
- [x] Implement `unblock_ip()` and temporary bans
- [x] Implement runtime IP whitelist
- [x] Add manual override hooks

---

## Phase 6: Optional Honeypot Verification (Week 6)
(Optional – Verification Support)

### Honeypot Integration
**Owner: Neha (Deployment) + Jisto (Integration)**
- [ ] Deploy low-interaction honeypot
- [ ] Activate honeypot only for low-trust/borderline cases
- [ ] Log interaction attempts
- [ ] Feed honeypot evidence into verification engine

---

## Phase 7: UI, Integration & Testing (Week 7)
(System Stabilization)

### UI & Dashboard
**Owner: Anees**
- [x] Dashboard Mockup UI
- [x] Dashboard for sensors, alerts, trust scores
- [x] Live alert monitor
- [x] Block / Unblock controls
- [x] System health indicators

### Integration & Testing
**Owner: Anees (Lead) + All Members**
- [ ] End-to-end integration testing
- [ ] Failure scenario testing (sensor down, API failure)
- [ ] Verification logic validation

**Note:**  
*Anees will deal with overall Testing and integration and UI.*

---

## Phase 8: Documentation & Final Demonstration (Week 8)

### Documentation
**Owner: Devika + Jisto**
- [ ] Update SRS and proposal documents
- [ ] Prepare architecture & flow diagrams

### Final Demo
**Owner: All Members**
- [ ] Demonstrate brute-force detection
- [ ] Demonstrate port scanning detection
- [ ] Demonstrate trust-based verification & enforcement

---

## Dependency Summary

Sensor stability → API security → DB & trust → verification → enforcement → honeypot → UI

No phase violates this order.

---
