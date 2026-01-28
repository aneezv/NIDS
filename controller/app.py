import logging
import threading
import json
import os
from enforce_auth import register_security
from models import db, SensorNode, Alert, BlockEvent
from datetime import datetime 
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

# --- API ENDPOINTS ---

@app.route('/alert', methods=['POST'])
def receive_alert():
    """
    Sensor sends: { "sensor_id": "node1", "ip": "1.2.3.4", "score": 85 }
    """
    data = request.json
    if not data or 'ip' not in data:
        return jsonify({"error": "Invalid Data"}), 400

    # 2. Async Processing (Fire and Forget)
    # The logic happens in the background.
    t = threading.Thread(target=engine.process_threat, args=(
        data.get('sensor_id', 'unknown'),
        data['ip'],
        float(data.get('score', 0))
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
    """
    Admin endpoint to update config
    """
    if request.method == 'POST':
        data = request.json
        if not data:
             return jsonify({"error": "No data received"}), 400
             
        allowed_keys = ['WHITELIST']
        
        for key, value in data.items():
            if key in allowed_keys:
                CONFIG[key] = value
                logger.info(f"🔧 Config updated: {key} = {value}")
                
        return jsonify({"status": "updated", "current_config": CONFIG}), 200

    return jsonify(CONFIG), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True, ssl_context=('cert.pem', 'key.pem'))