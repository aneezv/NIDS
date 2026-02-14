# Verification Phase Improvements

Analysis of the current `controller/verification.py` reveals several areas where improvements can be made to reduce false positives and enhance the verification logic.

## 1. Implement Sliding Time Window

**Current Issue:**
The current implementation retrieves *all* historical alerts for a source IP using:
```python
recent_alerts = Alert.query.filter_by(source_ip= ip).all()
```
This means an IP that generated a minor alert months ago will have that score permanently added to any new alert, potentially triggering a block for benign traffic.

**Recommendation:**
Implement a sliding time window (e.g., 1 hour or 24 hours) to only consider recent alerts. This ensures that the threat score reflects the *current* behavior of the IP.

**Suggested Code Change:**
```python
from datetime import datetime, timedelta
# ...
cutoff_time = datetime.utcnow() - timedelta(hours=1)
recent_alerts = Alert.query.filter(Alert.source_ip == ip, Alert.timestamp >= cutoff_time).all()
```

## 2. Fix Score Calculation Logic (Double Counting)

**Current Issue:**
The current logic appears to double-count the impact of the current alert:
1. The new alert is added to the session: `db.session.add(new_alert)`.
2. `Alert.query.filter_by(...)` retrieves all alerts, including the uncommitted `new_alert` (due to SQLAlchemy's autoflush).
3. `cumulative_score` sums all these scores (including the new one).
4. `total_threat` adds `weighted_impact` (which is the new alert's score weighted by trust) to `cumulative_score`.

Result: `total_threat = (Past Scores + Current Score) + (Current Score * Trust/100)`. This inflates the threat score.

**Recommendation:**
Adjust the logic to separate past cumulative score from the current alert's impact.

**Suggested Logic:**
```python
# Calculate score from PAST alerts only
past_alerts = Alert.query.filter(Alert.source_ip == ip, Alert.id != new_alert.id, Alert.timestamp >= cutoff_time).all()
cumulative_score = sum([a.score for a in past_alerts])

# Calculate impact of CURRENT alert
weighted_impact = raw_score * (current_trust / 100.0)

total_threat = cumulative_score + weighted_impact
```

## 3. Dynamic Trust Scoring

**Current Issue:**
Trust scores are initialized to 50.0 but there is no visible mechanism in `verification.py` to update them based on sensor performance (e.g., false positives vs. true positives).

**Recommendation:**
Implement a feedback loop. If an IP is unbanned (indicating a false positive), the trust score of the reporting sensor should be decreased. Conversely, if a block is verified as a true threat, the score could be increased.

## 4. Early Whitelist Check

**Current Issue:**
The whitelist is checked in `enforce_block`, which happens *after* all the DB operations and scoring logic.

**Recommendation:**
Check the whitelist at the very beginning of `process_threat`. If an IP is whitelisted, return immediately. This saves processing time and database writes for known benign IPs.

## 5. Correlate Alerts from Multiple Sensors

**Recommendation:**
If multiple distinct sensors report the same IP within a short window, this should significantly increase the confidence of the threat. The current logic treats all alerts linearly. Adding a multiplier for multi-sensor corroboration would reduce false positives from single rogue sensors.
