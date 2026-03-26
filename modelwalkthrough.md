# Walkthrough: Training a Better Model

## Changes Made
1. **Added [sensor/train_better_model.py](file:///c:/Projects/NIDS/sensor/train_better_model.py)**:
   - Replaced the simple Web/DNS synthetic packet generator with an enriched dataset generator.
   - Added normal profiles for **ICMP (Ping)**, **SSH/SFTP**, and **NTP (Time sync)** to accurately represent normal background noise.
   - Increased the Isolation Forest `n_estimators` to **200** to stabilize the ensemble predictions and tuned `contamination` to `0.01`.
2. **Generated `model_advanced.pkl`**:
   - Ran [train_better_model.py](file:///c:/Projects/NIDS/sensor/train_better_model.py) to create the new classifier.
3. **Updated [sensor/config.json](file:///c:/Projects/NIDS/sensor/config.json)**:
   - Updated the `model_path` to point to `model_advanced.pkl`.
   - Adjusted the `threshold` from `0.10` to `0.00`. Because the advanced model is trained on a richer dataset, its baseline `decision_function` margin tightened. A threshold of `0.00` correctly splits anomalies (negative scores) from normal traffic (positive scores).
4. **Created [sensor/verify_model.py](file:///c:/Projects/NIDS/sensor/verify_model.py)**:
   - Built a verification script using [AnomalyDetector](file:///c:/Projects/NIDS/sensor/detector.py#6-68) to feed raw packet features directly into the model for unit testing.

## Validated Results
The model was tested against a variety of synthetic payloads via [verify_model.py](file:///c:/Projects/NIDS/sensor/verify_model.py):
- **Normal Traffic**: HTTPS, ICMP (standard size), DNS, SSH all correctly scored `0.00%` anomaly confidence. The new model successfully recognizes diverse normal traffic.
- **Anomalous Traffic**: 
  - **Huge UDP Packet (Anomaly)**: Flagged with `30.06%` anomaly confidence.
  - **Huge Ping (Anomaly / Ping of Death)**: Flagged with `22.53%` anomaly confidence.

The advanced model acts as a much stabler baseline for the NIDS Controller's verification layer.
