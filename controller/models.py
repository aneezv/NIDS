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
    