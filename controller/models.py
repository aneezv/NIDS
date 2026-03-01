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

class HoneypotEvent(db.Model):
    __tablename__ = 'honeypot_event'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    source_ip = db.Column(db.String(50), index=True)
    port = db.Column(db.Integer)
    payload = db.Column(db.Text, nullable=True)
    tool_sig = db.Column(db.String(100), nullable=True)    # e.g. "nmap/7.94", "hydra/9.5"
    technique = db.Column(db.String(50), nullable=True)     # e.g. "brute_force", "banner_grab"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ThreatEscalation(db.Model):
    __tablename__ = 'threat_escalation'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String(50), unique=True, index=True)
    level = db.Column(db.Integer, default=1)                # 1=tarpit, 2=honeypot_exposed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    