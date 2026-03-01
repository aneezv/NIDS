import logging
from datetime import datetime, timedelta
from enforcement import enforce_block
from models import db, SensorNode, Alert, BlockEvent # [NEW]
from sqlalchemy import func, distinct

# Use child logger - inherits handlers from parent "NIDS_Controller"
logger = logging.getLogger("NIDS_Controller.Verification")

class VerificationEngine:
    def __init__(self, config,app):
        self.config = config
        self.app = app # [NEW] Need app context for DB

    def process_threat(self, sensor_id, ip, raw_score):
        """
        Decides if a threat is real.
        """
        with self.app.app_context():
            # 1. Initialize Trust if new sensor
            sensor = SensorNode.query.get(sensor_id)
            if not sensor:
                sensor = SensorNode(id=sensor_id,trust_score=50.0)
                db.session.add(sensor)
                db.session.commit()

            current_trust = sensor.trust_score

            new_alert = Alert(sensor_id = sensor_id,source_ip = ip, score= raw_score)
            db.session.add(new_alert)

            # 3. Calculate cumulative threat from recent alerts (last 1 hour)
            # We filter out the current alert (new_alert) to avoid double counting,
            # as we add its weighted score separately.
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            recent_alerts = Alert.query.filter(
                Alert.source_ip == ip,
                Alert.timestamp >= cutoff_time
            ).all()

            # 3a. Count how many distinct sensors reported this IP in the last hour
            distinct_sensors = db.session.query(
                func.count(distinct(Alert.sensor_id))
            ).filter(
                Alert.source_ip == ip,
                Alert.timestamp >= cutoff_time
            ).scalar()
            
            # Ensure the current sensor is counted if this is its first alert
            if distinct_sensors == 0:
                distinct_sensors = 1
            
            # decide how much extra confidence to add based on how many sensors reported this IP
            correlation_bonus = 0
            if distinct_sensors > 1:
                correlation_bonus = min((distinct_sensors -1) * 10,20)

            # Exclude the current alert we just added from the cumulative sum
            past_alerts = [a for a in recent_alerts if a is not new_alert]
            cumulative_score = sum([a.score for a in past_alerts])

            # Apply trust weighting to current alert
            weighted_impact = raw_score * (current_trust / 100.0)

            #final score includes correlation bonus
            total_threat = cumulative_score + weighted_impact + correlation_bonus

            logger.info(f"Analysis: IP={ip} | Sensors={distinct_sensors} | Threat={total_threat:.2f} (Bonus: {correlation_bonus}) | ReportedBy={sensor_id} (Trust: {current_trust})")

            # [NEW] Tiered Verification: Adjust required threshold based on sensor trust
            if current_trust >= 75:
                # High Trust: Use the standard threshold (e.g., 35)
                required_threshold = self.config['BLOCK_THRESHOLD']
            elif current_trust >= 40:
                # Medium Trust: Require 50% more evidence (e.g., 35 * 1.5 = 52.5)
                required_threshold = self.config['BLOCK_THRESHOLD'] * 1.5
            else:
                # Low Trust: Require 200% evidence (e.g., 35 * 2 = 70)
                required_threshold = self.config['BLOCK_THRESHOLD'] * 2.0
                
                # Bonus Rule: Low trust sensors CANNOT block an IP all by themselves without correlation
                if distinct_sensors < 2:
                    logger.warning(f"[DEFER] Sensor {sensor_id} has low trust ({current_trust:.1f}). Require multi-node confirmation. Blocking deferred.")
                    # Force the threshold impossibly high so it doesn't block right now
                    required_threshold = 999 

            # 4. The Verdict
            if total_threat > required_threshold:
                enforce_block(ip, {"score": total_threat}, self.config['WHITELIST'],self.app)

                # Record in database
                block_event = BlockEvent(ip=ip, reason=f"Threat Score: {total_threat:.2f}")
                db.session.add(block_event)

                # [NEW] Increase trust score for successful verification
                sensor.trust_score = min(100.0, sensor.trust_score + 5.0)

                logger.info(f"[SYSTEM] [BLOCK] {ip} blocked (Score: {total_threat:.2f})")
            else:
                # Only penalize if the score didn't even reach the baseline threshold. 
                # If it reached baseline but was deferred due to tier logic, don't penalize.
                if total_threat <= self.config['BLOCK_THRESHOLD']:
                    # [NEW] Decrease trust score slightly for unverified threats
                    sensor.trust_score = max(0.0, sensor.trust_score - 1.0)
                    logger.info(f"[SYSTEM] [VERIFY] {ip} threat unverified by Sensor {sensor.id} (Score: {total_threat:.2f})")
                else:
                    logger.info(f"[SYSTEM] [DEFERRED] {ip} threat reached baseline but wasn't blocked due to low trust (Score: {total_threat:.2f})")

            logger.info(f"[TRUST] Sensor {sensor.id} trust score updated to {sensor.trust_score:.2f}")

            # Commit all changes
            db.session.commit()

    def get_trust_scores(self):
        """Returns all sensor trust scores from DB"""
        with self.app.app_context():
            sensors = SensorNode.query.all()
            return {s.id: s.trust_score for s in sensors}
