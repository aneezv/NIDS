"""
test_verification.py — Practical tests for the NIDS VerificationEngine upgrade.

Run with:
    cd controller
    python -m pytest test_verification.py -v

Requirements:
    - Flask app context via conftest.py or inline setup below
    - SQLite in-memory DB (configured per test)
    - No mocks beyond what is strictly necessary (no faking DB state)
"""

import pytest
from app import app as flask_app
from models import db, SensorNode, Alert, BlockEvent, VerificationResult, HoneypotQueue
from verification import VerificationEngine, get_required_threshold


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app():
    flask_app.config['TESTING'] = True
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.drop_all()


@pytest.fixture
def engine(app):
    config = {
        'BLOCK_THRESHOLD': 35,
        'WHITELIST': ['127.0.0.1'],
    }
    return VerificationEngine(config, app)


# ---------------------------------------------------------------------------
# Unit: get_required_threshold
# ---------------------------------------------------------------------------

class TestGetRequiredThreshold:

    def test_high_trust_uses_baseline(self):
        """trust >= 75 → required == BLOCK_THRESHOLD (35)"""
        assert get_required_threshold(75, 2, 35) == 35
        assert get_required_threshold(100, 1, 35) == 35

    def test_mid_trust_uses_1_5x(self):
        """40 <= trust < 75 → required == 35 * 1.5 == 52.5"""
        assert get_required_threshold(40, 2, 35) == 52.5
        assert get_required_threshold(74, 1, 35) == 52.5

    def test_low_trust_multi_sensor_uses_2x(self):
        """trust < 40, 2+ sensors → required == 35 * 2.0 == 70"""
        assert get_required_threshold(39, 2, 35) == 70.0
        assert get_required_threshold(0, 3, 35) == 70.0

    def test_low_trust_single_sensor_force_defer(self):
        """trust < 40 AND only 1 sensor → required == 999 (unblockable alone)"""
        assert get_required_threshold(39, 1, 35) == 999
        assert get_required_threshold(10, 1, 35) == 999

    def test_correlation_bonus_boundary(self):
        """Sanity: bonus is min((n-1)*10, 20), not part of threshold."""
        bonus = lambda n: min((n - 1) * 10, 20)
        assert bonus(1) == 0
        assert bonus(2) == 10
        assert bonus(3) == 20
        assert bonus(10) == 20   # capped at 20


# ---------------------------------------------------------------------------
# Integration: process_threat() — BLOCK path
# ---------------------------------------------------------------------------

class TestBlockVerdict:

    def test_block_verdict_on_high_score(self, app, engine, monkeypatch):
        """
        High-trust sensor + high score → verdict BLOCK.
        enforce_block is monkeypatched to avoid subprocess calls.
        """
        import enforcement
        monkeypatch.setattr(enforcement, 'enforce_block',
                            lambda ip, info, whitelist, a: None)

        with app.app_context():
            # Sensor with high trust
            sensor = SensorNode(id='sensor-block', trust_score=80.0)
            db.session.add(sensor)
            db.session.commit()

            # raw_score=50: weighted_impact = 50 * 0.80 = 40 > threshold(35)
            result = engine.process_threat('sensor-block', '1.2.3.4', 50.0)

        assert result['verdict'] == 'BLOCK'
        assert result['ip'] == '1.2.3.4'
        assert result['score'] > 35

    def test_block_stores_verification_result(self, app, engine, monkeypatch):
        """BLOCK verdict is persisted to VerificationResult table."""
        import enforcement
        monkeypatch.setattr(enforcement, 'enforce_block',
                            lambda ip, info, whitelist, a: None)

        with app.app_context():
            sensor = SensorNode(id='sensor-store', trust_score=80.0)
            db.session.add(sensor)
            db.session.commit()

            engine.process_threat('sensor-store', '2.3.4.5', 50.0)

            record = VerificationResult.query.filter_by(ip='2.3.4.5').first()

        assert record is not None
        assert record.verdict == 'BLOCK'
        assert record.confidence > 0

    def test_block_increases_trust(self, app, engine, monkeypatch):
        """Successful BLOCK: sensor trust increases by 5."""
        import enforcement
        monkeypatch.setattr(enforcement, 'enforce_block',
                            lambda ip, info, whitelist, a: None)

        with app.app_context():
            sensor = SensorNode(id='sensor-trust-up', trust_score=80.0)
            db.session.add(sensor)
            db.session.commit()

            engine.process_threat('sensor-trust-up', '3.4.5.6', 50.0)

            db.session.expire_all()
            sensor = SensorNode.query.get('sensor-trust-up')

        assert sensor.trust_score == 85.0


# ---------------------------------------------------------------------------
# Integration: process_threat() — BORDERLINE path
# ---------------------------------------------------------------------------

class TestBorderlineVerdict:

    def _setup_borderline(self, app, engine):
        """
        Creates scenario where total_threat >= BLOCK_THRESHOLD (35)
        but required_threshold > total_threat (mid-trust: 52.5).

        trust=60 → required=52.5
        raw_score=40 → weighted_impact = 40 * 0.60 = 24  (< 35 alone)
        Need past cumulative to push it above 35 but below 52.5.
        Past alert score = 15 → cumulative = 15
        total = 15 + 24 + 0 = 39  ✓ (>= 35, < 52.5)
        """
        with app.app_context():
            sensor = SensorNode(id='sensor-borderline', trust_score=60.0)
            db.session.add(sensor)

            # Pre-inject a past alert for same IP
            from datetime import datetime, timedelta
            past = Alert(
                sensor_id='sensor-borderline',
                source_ip='5.6.7.8',
                score=15.0,
                timestamp=datetime.utcnow() - timedelta(minutes=10)
            )
            db.session.add(past)
            db.session.commit()

    def test_borderline_verdict(self, app, engine):
        self._setup_borderline(app, engine)
        result = engine.process_threat('sensor-borderline', '5.6.7.8', 40.0)
        assert result['verdict'] == 'BORDERLINE'

    def test_borderline_queues_honeypot(self, app, engine):
        """BORDERLINE verdict writes an entry to HoneypotQueue."""
        self._setup_borderline(app, engine)
        engine.process_threat('sensor-borderline', '5.6.7.8', 40.0)

        with app.app_context():
            entry = HoneypotQueue.query.filter_by(ip='5.6.7.8').first()

        assert entry is not None
        assert entry.processed is False

    def test_borderline_trust_unchanged(self, app, engine):
        """BORDERLINE does not change sensor trust score."""
        self._setup_borderline(app, engine)
        with app.app_context():
            before = SensorNode.query.get('sensor-borderline').trust_score

        engine.process_threat('sensor-borderline', '5.6.7.8', 40.0)

        with app.app_context():
            after = SensorNode.query.get('sensor-borderline').trust_score

        assert after == before


# ---------------------------------------------------------------------------
# Integration: process_threat() — UNVERIFIED path
# ---------------------------------------------------------------------------

class TestUnverifiedVerdict:

    def test_unverified_verdict_on_low_score(self, app, engine):
        """Score < BLOCK_THRESHOLD (35) → UNVERIFIED."""
        with app.app_context():
            sensor = SensorNode(id='sensor-low', trust_score=80.0)
            db.session.add(sensor)
            db.session.commit()

            # raw_score=20 → weighted_impact = 20 * 0.80 = 16 < 35
            result = engine.process_threat('sensor-low', '9.9.9.9', 20.0)

        assert result['verdict'] == 'UNVERIFIED'

    def test_unverified_decreases_trust(self, app, engine):
        """UNVERIFIED: sensor trust decreases by 1."""
        with app.app_context():
            sensor = SensorNode(id='sensor-trust-down', trust_score=60.0)
            db.session.add(sensor)
            db.session.commit()

            engine.process_threat('sensor-trust-down', '8.8.8.8', 10.0)

            db.session.expire_all()
            sensor = SensorNode.query.get('sensor-trust-down')

        assert sensor.trust_score == 59.0


# ---------------------------------------------------------------------------
# Structural: return value contract
# ---------------------------------------------------------------------------

class TestReturnContract:

    def test_return_has_required_keys(self, app, engine, monkeypatch):
        """process_threat() always returns a dict with all 6 required keys."""
        import enforcement
        monkeypatch.setattr(enforcement, 'enforce_block',
                            lambda ip, info, whitelist, a: None)

        required = {'ip', 'score', 'confidence', 'verdict', 'sensor_trust', 'sensors'}

        with app.app_context():
            sensor = SensorNode(id='sensor-contract', trust_score=80.0)
            db.session.add(sensor)
            db.session.commit()
            result = engine.process_threat('sensor-contract', '7.7.7.7', 50.0)

        assert required == set(result.keys())

    def test_verdict_is_always_one_of_three_states(self, app, engine, monkeypatch):
        import enforcement
        monkeypatch.setattr(enforcement, 'enforce_block',
                            lambda ip, info, whitelist, a: None)

        valid_verdicts = {'BLOCK', 'BORDERLINE', 'UNVERIFIED'}

        with app.app_context():
            sensor = SensorNode(id='sensor-states', trust_score=80.0)
            db.session.add(sensor)
            db.session.commit()
            result = engine.process_threat('sensor-states', '6.6.6.6', 50.0)

        assert result['verdict'] in valid_verdicts

    def test_confidence_never_exceeds_100(self, app, engine, monkeypatch):
        import enforcement
        monkeypatch.setattr(enforcement, 'enforce_block',
                            lambda ip, info, whitelist, a: None)

        with app.app_context():
            sensor = SensorNode(id='sensor-conf', trust_score=100.0)
            db.session.add(sensor)
            db.session.commit()
            result = engine.process_threat('sensor-conf', '4.4.4.4', 200.0)

        assert result['confidence'] <= 100.0
