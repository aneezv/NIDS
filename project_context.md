# Network Immune Defense System (NIDS) - Project Context

## 🎯 Core Problem
Anomaly-based IDS can detect unknown attacks but suffer from high false positives. Automatically blocking traffic based only on ML output is unsafe. This project solves that by separating detection, verification, and enforcement.

## 🧠 Design Principle
*   **ML is a signal, not an authority.**
*   **Detection ≠ Decision ≠ Enforcement**
*   No component alone can block traffic.
*   All actions are verified, temporary, and reversible.

## 🧬 Architecture Overview
`[ Live Network Traffic ]` → `[ IDS Sensors ]` → `[ Verification Layer (Controller) ]` → `[ Router-Level Enforcement ]`

## 🧩 Components

### 1️⃣ IDS Sensors
*   Capture live Internet traffic.
*   Extract flow-level features (rate, ports, bytes, failures).
*   Use **Isolation Forest** (unsupervised).
*   **Never block traffic.**
*   Send alerts to controller via HTTP.

### 2️⃣ Verification Layer (Core Contribution)
*   Aggregates independent evidence:
    *   Repeated anomalies over time.
    *   **Multi-sensor evidence aggregation** — the more distinct sensors report the same IP, the higher the score (capped). A *low-trust single sensor cannot* meet the threshold alone — it must be corroborated by another sensor.
    *   Short-term IP history (15-minute time-bucket persistence bonus).
    *   **Trust-weighted sensor alerts.**
    *   *Optional honeypot confirmation (evidence only).*
*   Computes a verification confidence score.
*   **Only if confidence exceeds a threshold is enforcement allowed.**
*   Trust influences confidence but never directly triggers blocking.

### 3️⃣ Enforcement Layer
*   Implemented at the router.
*   Uses `ipset` + `iptables`.
*   Network-wide blocking.
*   **Time-limited** (auto-expire).
*   **Reversible**.

### 4️⃣ Auto-ML Retraining (Constrained)
*   Isolation Forest retrains periodically on recent traffic.
*   **Controller-verified malicious IP traffic is excluded.**
*   Prevents concept drift without allowing model poisoning.
*   ML output still does not trigger enforcement.

## 🌐 Evaluation Strategy
*   Public datasets (CIC-IDS2017, UNSW-NB15) used only for *initial validation*.
*   **Live Internet traffic** used for:
    *   Demonstrating false positives.
    *   Verifying decision logic.
    *   Real enforcement behavior.
*   **No claims of perfect accuracy.** Focus on safe response and practical deployability.

## ❌ Explicit Non-Goals
*   No Blockchain, SDN, Deep Learning, Cloud-heavy systems.
*   No Permanent automated bans.

## 🎓 Framing Constraints
*   Mini-project (not PhD-level research).
*   Novelty is system & enforcement level, not algorithmic.
*   Claims must be honest and viva-defensible.
