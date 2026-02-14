import logging
import threading
import json
import os
from models import db, SensorNode, Alert, BlockEvent
from datetime import datetime 
import secrets
import ipaddress

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from verification import VerificationEngine
load_dotenv()
# --- CONFIGURATION ---
with open('config.json') as f:
    CONFIG = json.load(f)
if os.getenv("API_KEY"):
    CONFIG["API_KEY"] = os.getenv("API_KEY")    
app = Flask(__name__)
app.config.update(CONFIG)
# register_security(app)

# [NEW] Database Configuration - USE ABSOLUTE PATH!
import os
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'nids.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# NOTE: Tables created manually via create_db_manual.py
# Do NOT use db.create_all() - it wipes existing data!

# --- LOGGING ---
import sys
logger = logging.getLogger("NIDS_Controller")

logger.setLevel(logging.INFO)
logger.propagate = False  # Prevent double logging!

# File handler for audit log (UTF-8 for emojis)
audit_handler = logging.FileHandler('audit.log', encoding='utf-8')
audit_handler.setLevel(logging.INFO)
audit_handler.setFormatter(logging.Formatter('%(asctime)s - [%(name)s] %(message)s'))
logger.addHandler(audit_handler)

# Console handler (UTF-8 stream for Windows)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(console_handler)

# --- CORE ENGINE ---
engine = VerificationEngine(CONFIG,app)
# --- SECURITY HELPERS ---
def check_auth():
    """
    Validates the X-NIDS-Auth header using constant-time comparison.
    Returns True if valid, False otherwise.
    """
    api_key = request.headers.get('X-NIDS-Auth')
    if not api_key:
        return False
    
    # Ensure both are strings for compare_digest
    valid_key = str(CONFIG.get('API_KEY', ''))
    return secrets.compare_digest(api_key, valid_key)
def validate_alert_data(data):
    """
    Strict validation for alert payloads.
    Returns: (is_valid: bool, error_msg: str)
    """
    if not data:
        return False, "Empty Payload"
    # 1. Check Required Keys
    required = ['sensor_id', 'ip', 'score']
    if not all(k in data for k in required):
        return False, f"Missing fields. Required: {required}"
    # 2. Check IP Format
    try:
        ipaddress.ip_address(data['ip'])
    except ValueError:
        return False, f"Invalid IP format: {data['ip']}"
    return True, None
    
# --- API ENDPOINTS ---
@app.route('/alert', methods=['POST'])
def receive_alert():
    """
    Sensor sends: { "sensor_id": "node1", "ip": "1.2.3.4", "score": 85 }
    """
    # 1. Security Check (Hardened)
    if not check_auth():
        logger.warning(f"⛔ Unauthorized Alert attempt from {request.remote_addr}")
        return jsonify({"error": "Unauthorized"}), 401
    # 2. Payload Validation (Strict)
    data = request.json
    is_valid, error = validate_alert_data(data)
    if not is_valid:
        logger.warning(f"⚠️ Invalid Payload from {request.remote_addr}: {error}")
        return jsonify({"error": error}), 400
    # 3. Async Processing (Fire and Forget)
    # The logic happens in the background.
    t = threading.Thread(target=engine.process_threat, args=(
        data.get('sensor_id'),
        data.get('ip'),
        float(data.get('score'))
    ))
    t.start()
    return jsonify({"status": "processing", "message": "Alert received"}), 200

# [NEW] Management API: List Nodes
@app.route('/api/nodes', methods=['GET'])
def list_nodes():
    nodes = SensorNode.query.all()
    return jsonify([{
        "id": n.id, 
        "ip": n.ip, 
        "trust": n.trust_score, 
        "status": n.status,
        "last_seen": n.last_seen.isoformat() if n.last_seen else None
    } for n in nodes])

# [NEW] Management API: List Alerts
@app.route('/api/alerts', methods=['GET'])
def list_alerts():
    limit = request.args.get('limit', 50, type=int)
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
    return jsonify([{
        "id": a.id,
        "sensor": a.sensor_id,
        "ip": a.source_ip,
        "score": a.score,
        "time": a.timestamp.isoformat()
    } for a in alerts])

# [NEW] Management API: System Status
@app.route('/api/status', methods=['GET'])
def system_status():
    node_count = SensorNode.query.count()
    alert_count = Alert.query.count()
    block_count = BlockEvent.query.count()
    return jsonify({
        "active_sensors": node_count,
        "total_alerts": alert_count,
        "active_blocks": block_count
    })

# [NEW] Management API: Unban
@app.route('/api/action/unban', methods=['POST'])
def unban_ip():
    data = request.json
    ip = data.get('ip')
    
    # Logic to call unblock script would go here (Jisto's task)
    logger.info(f"[ADMIN] [UNBAN] Request to unban {ip}")
    
    # Remove from BlockEvent DB
    BlockEvent.query.filter_by(ip=ip).delete()
    db.session.commit()
    
    return jsonify({"status": "unbanned", "ip": ip})


 #Heartbeat
@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    # 1. Security Check (Added)
    # Previously missing in work_flow check phase 2!
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    sensor_id = data.get('sensor_id')
    
    # [NEW] Update Sensor in DB
    node = SensorNode.query.get(sensor_id)
    if not node:
        node = SensorNode(id=sensor_id, ip=request.remote_addr)
        db.session.add(node)
    
    node.last_seen = datetime.utcnow()
    node.status = "online"
    db.session.commit()
    
    return jsonify({"status": "ok"}), 200
    
@app.route('/config', methods=['POST', 'GET'])
def manage_config():
    # 1. Verify Admin Key (Hardened)
    if not check_auth():
         return jsonify({"error": "Unauthorized"}), 401
    
    # 2. Handle Updates
    if request.method == 'POST':
        data = request.json
        if not data:
             return jsonify({"error": "No data received"}), 400
             
        # MODIFIED: Only allow WHITELIST updates for now
        allowed_keys = ['WHITELIST']
        
        for key, value in data.items():
            if key in allowed_keys:
                CONFIG[key] = value
                logger.info(f"🔧 Config updated: {key} = {value}")
                
        return jsonify({"status": "updated", "current_config": CONFIG}), 200
    # 3. Return current config (GET)
    return jsonify(CONFIG), 200
@app.route('/trust', methods=['GET'])
def get_trust():
    """Admin endpoint to view sensor health"""
    # Optional: Protect this too? Leaving public for dashboard for now.
    return jsonify(engine.get_trust_scores())
if __name__ == '__main__':
    # Fail if certs are missing. No fallback to HTTP allowed.
    app.run(host='0.0.0.0', port=5000, threaded=True, ssl_context=('cert.pem', 'key.pem'))