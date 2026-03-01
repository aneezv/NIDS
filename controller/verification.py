import logging
import json
import subprocess
from datetime import datetime, timedelta
from enforcement import enforce_block
from models import db, SensorNode, Alert, BlockEvent, HoneypotEvent, ThreatEscalation

# Use child logger - inherits handlers from parent "NIDS_Controller"
logger = logging.getLogger("NIDS_Controller.Verification")

class VerificationEngine:
    def __init__(self, config, app):
        self.config = config
        self.app = app

    def process_threat(self, sensor_id, ip, raw_score):
        """
        Decides if a threat is real using graduated verification:
        1. Historical honeypot correlation
        2. Evasion detection
        3. Trust-weighted scoring
        4. Graduated response (tarpit → expose → block)
        """
        with self.app.app_context():
            # 1. Initialize Trust if new sensor
            sensor = SensorNode.query.get(sensor_id)
            if not sensor:
                sensor = SensorNode(id=sensor_id, trust_score=50.0)
                db.session.add(sensor)
                db.session.commit()

            current_trust = sensor.trust_score

            # Record the alert
            new_alert = Alert(sensor_id=sensor_id, source_ip=ip, score=raw_score)
            db.session.add(new_alert)

            # --- LAYER 1: Historical Honeypot Correlation ---
            honeypot_hits = HoneypotEvent.query.filter_by(source_ip=ip).count()
            if honeypot_hits > 0:
                logger.info(f"🚨 [HONEYPOT CORRELATION] {ip} has {honeypot_hits} historical honeypot interactions — VERIFIED MALICIOUS")
                self._execute_block(ip, 100.0, sensor, "Honeypot Correlation")
                self._ml_feedback(ip, raw_score, "honeypot_correlation")
                db.session.commit()
                return

            # --- LAYER 2: Cumulative Threat Calculation ---
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            recent_alerts = Alert.query.filter(
                Alert.source_ip == ip,
                Alert.timestamp >= cutoff_time
            ).all()

            past_alerts = [a for a in recent_alerts if a is not new_alert]
            cumulative_score = sum([a.score for a in past_alerts])

            # Apply trust weighting to current alert
            weighted_impact = raw_score * (current_trust / 100.0)
            total_threat = cumulative_score + weighted_impact

            logger.info(f"Analysis: IP={ip} | Threat={total_threat:.2f} | ReportedBy={sensor_id} (Trust: {current_trust})")

            # --- THRESHOLDS ---
            block_threshold = self.config.get('BLOCK_THRESHOLD', 80)
            warning_threshold = self.config.get('WARNING_THRESHOLD', block_threshold * 0.5)

            # --- VERDICT ---
            if total_threat > block_threshold:
                # DEFINITIVE BLOCK
                self._execute_block(ip, total_threat, sensor, f"Threat Score: {total_threat:.2f}")

                # Increase trust for sensor that helped verify
                sensor.trust_score = min(100.0, sensor.trust_score + 5.0)
                logger.info(f"[SYSTEM] [BLOCK] {ip} blocked (Score: {total_threat:.2f})")

                # ML Feedback
                self._ml_feedback(ip, raw_score, "threshold_exceeded")

            elif total_threat > warning_threshold and current_trust < 40:
                # BORDERLINE CASE — Graduated Response
                logger.info(f"⚠️ [BORDERLINE] {ip} threat={total_threat:.2f} from low-trust sensor {sensor_id} (trust={current_trust})")

                # Check for evasion
                evasion_detected = self._detect_evasion(ip)

                # Check existing escalation state
                escalation = ThreatEscalation.query.filter_by(ip=ip).first()

                if evasion_detected:
                    # Skip to Level 2 — sophisticated attacker
                    logger.info(f"🕵️ [EVASION] {ip} is avoiding honeypot ports — escalating to honeypot exposure")
                    self._escalate_to_level(ip, 2, escalation)
                elif escalation and escalation.level == 1:
                    # Already tarpitted + still sending alerts → escalate
                    logger.info(f"📈 [ESCALATE] {ip} still active during tarpit — exposing honeypot")
                    self._escalate_to_level(ip, 2, escalation)
                else:
                    # Level 1: Tarpit
                    logger.info(f"⏳ [TARPIT] Applying rate-limit to {ip}")
                    self._escalate_to_level(ip, 1, escalation)

                # Slight trust penalty for unverified borderline reports
                sensor.trust_score = max(0.0, sensor.trust_score - 0.5)
            else:
                # LOW THREAT — Just log
                sensor.trust_score = max(0.0, sensor.trust_score - 1.0)
                logger.info(f"[SYSTEM] [VERIFY] {ip} threat unverified by Sensor {sensor.id} (Score: {total_threat:.2f})")

            logger.info(f"[TRUST] Sensor {sensor.id} trust score updated to {sensor.trust_score:.2f}")

            # Commit all changes
            db.session.commit()

    def _execute_block(self, ip, score, sensor, reason):
        """Block an IP and clean up any escalation state."""
        enforce_block(ip, {"score": score}, self.config.get('WHITELIST', []), self.app)

        # Record in database
        block_event = BlockEvent(ip=ip, reason=reason)
        db.session.add(block_event)

        # Cleanup: remove any escalation rules (tarpit/honeypot allow)
        escalation = ThreatEscalation.query.filter_by(ip=ip).first()
        if escalation:
            self._cleanup_escalation(ip, escalation)

    def _detect_evasion(self, ip):
        """
        Detects honeypot evasion: heavy scanning with zero honeypot interactions.
        """
        alert_count = Alert.query.filter_by(source_ip=ip).count()
        honeypot_hits = HoneypotEvent.query.filter_by(source_ip=ip).count()

        # Heavy scanning (5+ alerts) but zero honeypot hits = deliberate avoidance
        if alert_count >= 5 and honeypot_hits == 0:
            logger.info(f"🕵️ [EVASION DETECTED] {ip}: {alert_count} alerts but 0 honeypot interactions")
            return True
        return False

    def _escalate_to_level(self, ip, level, existing_escalation):
        """Apply graduated response at the given level."""
        if existing_escalation:
            existing_escalation.level = level
            if level == 2:
                existing_escalation.expires_at = datetime.utcnow() + timedelta(minutes=60)
            else:
                existing_escalation.expires_at = datetime.utcnow() + timedelta(minutes=30)
        else:
            ttl = timedelta(minutes=30) if level == 1 else timedelta(minutes=60)
            escalation = ThreatEscalation(
                ip=ip,
                level=level,
                expires_at=datetime.utcnow() + ttl
            )
            db.session.add(escalation)

        # Execute the actual firewall commands
        if level == 1:
            try:
                subprocess.run(["sudo", "./tarpit_ip.sh", ip], check=True)
                logger.info(f"[TARPIT] Applied rate-limiting to {ip} (TTL: 30 min)")
            except Exception as e:
                logger.error(f"[TARPIT] Failed: {e}")

        elif level == 2:
            try:
                subprocess.run(["sudo", "./allow_honeypot.sh", ip], check=True)
                logger.info(f"[HONEYPOT] Exposed decoy ports to {ip} (TTL: 60 min)")
            except Exception as e:
                logger.error(f"[HONEYPOT] Failed: {e}")

    def _cleanup_escalation(self, ip, escalation):
        """Remove all graduated response rules for an IP."""
        try:
            if escalation.level >= 1:
                subprocess.run(["sudo", "./untarpit_ip.sh", ip], check=True)
            if escalation.level >= 2:
                subprocess.run(["sudo", "./revoke_honeypot.sh", ip], check=True)
        except Exception as e:
            logger.error(f"[CLEANUP] Failed to cleanup escalation for {ip}: {e}")

        db.session.delete(escalation)
        logger.info(f"[CLEANUP] Removed escalation rules for {ip}")

    def _ml_feedback(self, ip, raw_score, verification_method):
        """Save verified threat as labeled training data for sensor ML retraining."""
        training_sample = {
            "ip": ip,
            "raw_score": raw_score,
            "label": "VERIFIED_ATTACK",
            "verified_by": verification_method,
            "timestamp": datetime.utcnow().isoformat()
        }
        try:
            with open('verified_threats.jsonl', 'a') as f:
                json.dump(training_sample, f)
                f.write('\n')
            logger.info(f"[ML] Saved verified threat for {ip} to training data")
        except Exception as e:
            logger.error(f"[ML] Failed to save training data: {e}")

    def get_trust_scores(self):
        """Returns all sensor trust scores from DB"""
        with self.app.app_context():
            sensors = SensorNode.query.all()
            return {s.id: s.trust_score for s in sensors}

    def cleanup_expired_escalations(self):
        """TTL daemon: called periodically to remove expired tarpit/honeypot rules."""
        with self.app.app_context():
            now = datetime.utcnow()
            expired = ThreatEscalation.query.filter(ThreatEscalation.expires_at <= now).all()

            for esc in expired:
                logger.info(f"⏰ [TTL EXPIRED] Cleaning up escalation for {esc.ip} (Level {esc.level})")
                self._cleanup_escalation(esc.ip, esc)

            if expired:
                db.session.commit()
                logger.info(f"[TTL] Cleaned up {len(expired)} expired escalations")
