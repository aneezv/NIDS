import logging
from datetime import datetime, timedelta
from enforcement import enforce_block
from models import db, SensorNode, Alert, BlockEvent, VerificationResult, HoneypotQueue
from models import db, SensorNode, Alert, BlockEvent, VerificationResult, HoneypotQueue
from sqlalchemy import func, distinct

# Use child logger - inherits handlers from parent "NIDS_Controller"
logger = logging.getLogger("NIDS_Controller.Verification")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_required_threshold(trust, distinct_sensors, block_threshold):
    """
    Returns the trust-adjusted score threshold needed to trigger enforcement.

    Decision table (BLOCK_THRESHOLD = 35 by default):
        trust >= 75  → block_threshold          (35)   — high trust, standard bar
        trust >= 40  → block_threshold * 1.5    (52.5) — mid trust, harder bar
        trust <  40  → block_threshold * 2.0    (70)   — low trust, very hard bar
        trust <  40 and single sensor → 999             — force defer, not blockable alone
    """
    if trust >= 75:
        return block_threshold
    elif trust >= 40:
        return block_threshold * 1.5
    else:
        if distinct_sensors < 2:
            return 999          # Low-trust single sensor: cannot block unilaterally
        return block_threshold * 2.0


def trigger_honeypot(ip, score, app):
    """
    Enqueues an IP for honeypot follow-up by writing it to the HoneypotQueue table.
    This is a real action — not a placeholder. The honeypot worker (Phase 6) reads
    this table and processes unhandled entries (processed=False).
    """
    with app.app_context():
        entry = HoneypotQueue(ip=ip, score=score)
        db.session.add(entry)
        db.session.commit()
    logger.info(f"[HONEYPOT] {ip} queued for honeypot verification (Score: {score:.2f})")


# ---------------------------------------------------------------------------
# Verification Engine
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_required_threshold(trust, distinct_sensors, block_threshold):
    """
    Returns the trust-adjusted score threshold needed to trigger enforcement.

    Decision table (BLOCK_THRESHOLD = 35 by default):
        trust >= 75  → block_threshold          (35)   — high trust, standard bar
        trust >= 40  → block_threshold * 1.5    (52.5) — mid trust, harder bar
        trust <  40  → block_threshold * 2.0    (70)   — low trust, very hard bar
        trust <  40 and single sensor → 999             — force defer, not blockable alone
    """
    if trust >= 75:
        return block_threshold
    elif trust >= 40:
        return block_threshold * 1.5
    else:
        if distinct_sensors < 2:
            return 999          # Low-trust single sensor: cannot block unilaterally
        return block_threshold * 2.0


def trigger_honeypot(ip, score, app):
    """
    Enqueues an IP for honeypot follow-up by writing it to the HoneypotQueue table.
    This is a real action — not a placeholder. The honeypot worker (Phase 6) reads
    this table and processes unhandled entries (processed=False).
    """
    with app.app_context():
        entry = HoneypotQueue(ip=ip, score=score)
        db.session.add(entry)
        db.session.commit()
    logger.info(f"[HONEYPOT] {ip} queued for honeypot verification (Score: {score:.2f})")


# ---------------------------------------------------------------------------
# Verification Engine
# ---------------------------------------------------------------------------

class VerificationEngine:
    def __init__(self, config, app):
        self.config = config
        self.app = app

    def process_threat(self, sensor_id, ip, raw_score):
        """
        Evaluates an incoming alert and produces a verified verdict.

        Decision states:
            BLOCK       — total_threat > required_threshold    → enforce firewall block
            BORDERLINE  — total_threat >= BLOCK_THRESHOLD but
                          total_threat <= required_threshold   → queue for honeypot
            UNVERIFIED  — total_threat < BLOCK_THRESHOLD       → insufficient evidence

        Returns:
            dict: { ip, score, confidence, verdict, sensor_trust, sensors }
        Evaluates an incoming alert and produces a verified verdict.

        Decision states:
            BLOCK       — total_threat > required_threshold    → enforce firewall block
            BORDERLINE  — total_threat >= BLOCK_THRESHOLD but
                          total_threat <= required_threshold   → queue for honeypot
            UNVERIFIED  — total_threat < BLOCK_THRESHOLD       → insufficient evidence

        Returns:
            dict: { ip, score, confidence, verdict, sensor_trust, sensors }
        """
        with self.app.app_context():

            # ------------------------------------------------------------------
            # 1. Init sensor if new (default trust = 50.0)
            # ------------------------------------------------------------------

            # ------------------------------------------------------------------
            # 1. Init sensor if new (default trust = 50.0)
            # ------------------------------------------------------------------
            sensor = SensorNode.query.get(sensor_id)
            if not sensor:
                sensor = SensorNode(id=sensor_id, trust_score=50.0)
                sensor = SensorNode(id=sensor_id, trust_score=50.0)
                db.session.add(sensor)
                db.session.commit()

            current_trust = sensor.trust_score

            # ------------------------------------------------------------------
            # 2. Record incoming alert
            # ------------------------------------------------------------------
            new_alert = Alert(sensor_id=sensor_id, source_ip=ip, score=raw_score)
            # ------------------------------------------------------------------
            # 2. Record incoming alert
            # ------------------------------------------------------------------
            new_alert = Alert(sensor_id=sensor_id, source_ip=ip, score=raw_score)
            db.session.add(new_alert)

            # ------------------------------------------------------------------
            # 3. Cumulative threat — all alerts for this IP in the last 1 hour
            # ------------------------------------------------------------------
            # ------------------------------------------------------------------
            # 3. Cumulative threat — all alerts for this IP in the last 1 hour
            # ------------------------------------------------------------------
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            recent_alerts = Alert.query.filter(
                Alert.source_ip == ip,
                Alert.timestamp >= cutoff_time
            ).all()

            # 3a. Count distinct sensors reporting this IP (for correlation)
            # 3a. Count distinct sensors reporting this IP (for correlation)
            distinct_sensors = db.session.query(
                func.count(distinct(Alert.sensor_id))
            ).filter(
                Alert.source_ip == ip,
                Alert.timestamp >= cutoff_time
            ).scalar()


            if distinct_sensors == 0:
                distinct_sensors = 1

            # 3b. Correlation bonus: +10 per extra sensor, capped at +20

            # 3b. Correlation bonus: +10 per extra sensor, capped at +20
            correlation_bonus = 0
            if distinct_sensors > 1:
                correlation_bonus = min((distinct_sensors - 1) * 10, 20)

            # 3c. Sum past alert scores (exclude current to avoid double-count)
            past_alerts = [a for a in recent_alerts if a is not new_alert]
            cumulative_score = sum(a.score for a in past_alerts)

            # 3d. Trust-weighted impact for the current alert
            weighted_impact = raw_score * (current_trust / 100.0)

            # 3e. Base final threat score
            total_threat = cumulative_score + weighted_impact + correlation_bonus

            # 3f. IP Persistence Bonus (N3)
            # Group alerts into 15-minute buckets. If an IP appears in 3+ distinct buckets
            # within the last hour, add a +5.0 persistence bonus to the threat score.
            persistence_bonus = 0.0
            if len(recent_alerts) >= 3:
                distinct_buckets = set()
                for alert in recent_alerts:
                    bucket_group = alert.timestamp.minute // 15
                    bucket_id = f"{alert.timestamp.strftime('%Y-%m-%d-%H')}-{bucket_group}"
                    distinct_buckets.add(bucket_id)
                    
                if len(distinct_buckets) >= 3:
                    persistence_bonus = 5.0
                    total_threat += persistence_bonus
                    logger.warning(
                        f"[PATTERN] Persistent threat detected for {ip} across "
                        f"{len(distinct_buckets)} time windows. Applied +5.0 bonus."
                    )

            logger.info(
                f"Analysis: IP={ip} | Sensors={distinct_sensors} | "
                f"Threat={total_threat:.2f} (Corr: {correlation_bonus}, Pers: {persistence_bonus}) | "
                f"ReportedBy={sensor_id} (Trust: {current_trust})"
            )

            # ------------------------------------------------------------------
            # 4. Compute trust-adjusted required threshold
            # ------------------------------------------------------------------
            required_threshold = get_required_threshold(
                current_trust, distinct_sensors, self.config['BLOCK_THRESHOLD']
            )

            # ------------------------------------------------------------------
            # 5. Verdict — exactly one branch executes; verdict always assigned
            # ------------------------------------------------------------------
            if total_threat > required_threshold:
                # --- BLOCK ---
                verdict = "BLOCK"
                enforce_block(ip, {"score": total_threat}, self.config['WHITELIST'], self.app)
                block_event = BlockEvent(ip=ip, reason=f"Threat Score: {total_threat:.2f}")
                db.session.add(block_event)
                sensor.trust_score = min(100.0, sensor.trust_score + 5.0)
                logger.info(f"[SYSTEM] [BLOCK] {ip} blocked (Score: {total_threat:.2f})")

            elif total_threat >= self.config['BLOCK_THRESHOLD']:
                # --- BORDERLINE ---
                # Score reached the baseline threshold but trust-tier prevents
                # enforcement. Enqueue for honeypot follow-up — real DB write.
                verdict = "BORDERLINE"
                trigger_honeypot(ip, total_threat, self.app)
                logger.warning(
                    f"[BORDERLINE] {ip} — Score {total_threat:.2f} reached baseline "
                    f"(required for block: {required_threshold:.1f}). "
                    f"Queued for honeypot."
                )

            else:
                # --- UNVERIFIED ---
                # Score did not reach even the baseline threshold.
                verdict = "UNVERIFIED"
                sensor.trust_score = max(0.0, sensor.trust_score - 1.0)
                logger.info(
                    f"[SYSTEM] [VERIFY] {ip} threat unverified by Sensor {sensor.id} "
                    f"(Score: {total_threat:.2f})"
                )

            logger.info(
                f"[TRUST] Sensor {sensor.id} trust score updated to {sensor.trust_score:.2f}"
            )

            # ------------------------------------------------------------------
            # 6. Confidence score
            #    Formula: (total_threat / required_threshold) * 100, capped at 100.
            #    Division-by-zero safe: required_threshold is minimum 35 (config)
            #    or 999 (forced defer). Never 0.
            # ------------------------------------------------------------------
            confidence = min(100.0, round((total_threat / required_threshold) * 100, 1))

            # ------------------------------------------------------------------
            # 7. Persist result — makes verdict visible system-wide via /api/verdicts
            # ------------------------------------------------------------------
            result_record = VerificationResult(
                ip=ip,
                score=round(total_threat, 2),
                confidence=confidence,
                verdict=verdict,
                sensor_trust=current_trust,
                sensors=distinct_sensors
            )
            db.session.add(result_record)

            # Commit all changes in one transaction
            db.session.commit()

            return {
                "ip": ip,
                "score": round(total_threat, 2),
                "confidence": confidence,
                "verdict": verdict,
                "sensor_trust": current_trust,
                "sensors": distinct_sensors
            }

    def get_trust_scores(self):
        """Returns all sensor trust scores from DB."""
        with self.app.app_context():
            sensors = SensorNode.query.all()
            return {s.id: s.trust_score for s in sensors}
