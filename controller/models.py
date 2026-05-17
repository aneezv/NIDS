from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
db = SQLAlchemy()

class SensorNode(db.Model):
    __tablename__ = 'sensor_node'
    id = db.Column(db.String(50), primary_key=True)
    ip = db.Column(db.String(50))
    trust_score = db.Column(db.Float, default=50.0)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="offline")
    cpu_load = db.Column(db.Float, nullable=True)

class Alert(db.Model):
    __tablename__ = 'alert'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sensor_id = db.Column(db.String(50), db.ForeignKey('sensor_node.id'))
    source_ip = db.Column(db.String(50))
    score = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class BlockEvent(db.Model):
    __tablename__ = 'block_event'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String(50))
    reason = db.Column(db.String(100))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)

class VerificationResult(db.Model):
    """Stores every verdict produced by process_threat() for system-wide visibility."""
    __tablename__ = 'verification_result'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Float, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    verdict = db.Column(db.String(20), nullable=False)   # BLOCK | BORDERLINE | UNVERIFIED
    sensor_trust = db.Column(db.Float, nullable=False)
    sensors = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class HoneypotQueue(db.Model):
    """IPs queued for honeypot follow-up when verdict is BORDERLINE."""
    __tablename__ = 'honeypot_queue'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Float, nullable=False)
    queued_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed = db.Column(db.Boolean, default=False)