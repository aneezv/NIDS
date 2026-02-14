import logging
from datetime import datetime, timedelta
from enforcement import enforce_block
from models import db, SensorNode, Alert, BlockEvent # [NEW]

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

            # Exclude the current alert we just added from the cumulative sum
            past_alerts = [a for a in recent_alerts if a is not new_alert]
            cumulative_score = sum([a.score for a in past_alerts])

            # Apply trust weighting to current alert
            weighted_impact = raw_score * (current_trust / 100.0)
            total_threat = cumulative_score + weighted_impact

            logger.info(f"Analysis: IP={ip} | Threat={total_threat:.2f} | ReportedBy={sensor_id} (Trust: {current_trust})")

            # 4. The Verdict
            if total_threat > self.config['BLOCK_THRESHOLD']:
                enforce_block(ip, {"score": total_threat}, self.config['WHITELIST'],self.app)

                # Record in database
                block_event = BlockEvent(ip=ip, reason=f"Threat Score: {total_threat:.2f}")
                db.session.add(block_event)

                logger.info(f"[SYSTEM] [BLOCK] {ip} blocked (Score: {total_threat:.2f})")

            # Commit all changes
            db.session.commit()

    def get_trust_scores(self):
        """Returns all sensor trust scores from DB"""
        with self.app.app_context():
            sensors = SensorNode.query.all()
            return {s.id: s.trust_score for s in sensors}
