import logging
import threading
import json
import os
from models import db, SensorNode, Alert, BlockEvent, VerificationResult, HoneypotQueue
from datetime import datetime 
import secrets
import ipaddress

from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_from_directory
from verification import VerificationEngine
from enforcement import remove_ban, enforce_block
load_dotenv()
import socket

# --- CONFIGURATION ---
with open('config.json') as f:
    CONFIG = json.load(f)

# Auto-whitelist the controller's own IP so it never blocks itself
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

controller_ip = get_local_ip()
if 'WHITELIST' not in CONFIG:
    CONFIG['WHITELIST'] = []
if controller_ip not in CONFIG['WHITELIST']:
    CONFIG['WHITELIST'].append(controller_ip)
if "127.0.0.1" not in CONFIG['WHITELIST']:
    CONFIG['WHITELIST'].append("127.0.0.1")
CONFIG["API_KEY"] = os.getenv("API_KEY") or CONFIG.get("API_KEY")
if not CONFIG.get("API_KEY"):
    raise RuntimeError(
        "API_KEY is not set. Add it to controller/.env (preferred) or controller/config.json."
    )

app = Flask(__name__)
app.config.update(CONFIG)

from enforce_auth import register_security
register_security(app)

# [NEW] Database Configuration - USE ABSOLUTE PATH!
import os
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'nids.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "connect_args": {
        "timeout": 15
    }
}
db.init_app(app)

# NOTE: Initialize or migrate the database using setup_db.py

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
        "cpu_load": n.cpu_load,
        "last_seen": n.last_seen.isoformat() if n.last_seen else None
    } for n in nodes])

# [NEW] Management API: Delete Node
@app.route('/api/nodes/<sensor_id>', methods=['DELETE'])
def delete_node(sensor_id):
    if not check_auth():
         return jsonify({"error": "Unauthorized"}), 401
    
    node = SensorNode.query.get(sensor_id)
    if not node:
         return jsonify({"error": "Sensor not found"}), 404
         
    db.session.delete(node)
    db.session.commit()
    logger.info(f"[ADMIN] Deleted sensor {sensor_id}")
    return jsonify({"status": "deleted", "id": sensor_id}), 200

# [NEW] Management API: List Alerts
@app.route('/api/alerts', methods=['GET'])
def list_alerts():
    limit = max(1, min(request.args.get('limit', 50, type=int), 500))
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
    if not check_auth():
         return jsonify({"error": "Unauthorized"}), 401
         
    data = request.json
    ip = data.get('ip')
    if not ip:
         return jsonify({"error": "IP is required"}), 400
    
    # Logic to call unblock script
    logger.info(f"[ADMIN] [UNBAN] Request to unban {ip}")
    remove_ban(ip)
    
    # Remove from BlockEvent DB
    BlockEvent.query.filter_by(ip=ip).delete()
    db.session.commit()
    
    return jsonify({"status": "unbanned", "ip": ip})

# [NEW] Management API: Manual Block
@app.route('/api/action/block', methods=['POST'])
def block_ip_manual():
    if not check_auth():
         return jsonify({"error": "Unauthorized"}), 401
         
    data = request.json
    ip = data.get('ip')
    if not ip:
         return jsonify({"error": "IP is required"}), 400
    
    logger.info(f"[ADMIN] [BLOCK] Request to manually block {ip}")
    
    whitelist = CONFIG.get('WHITELIST', [])
    if ip in whitelist:
         logger.warning(f"[ADMIN] [BLOCK] Rejected: {ip} is whitelisted.")
         return jsonify({"error": f"Cannot block {ip} (Whitelisted)"}), 400
         
    # duration=0 for permanent blocks in ipset
    enforce_block(ip, {"score": 100.0}, whitelist, app, duration=0)
    
    # Record in database (expires_at gets None automatically = permanent)
    block_event = BlockEvent(ip=ip, reason=f"Manual Override Block")
    db.session.add(block_event)
    db.session.commit()
    
    return jsonify({"status": "blocked", "ip": ip})

# [NEW] Management API: Whitelist
@app.route('/api/action/whitelist', methods=['POST'])
def whitelist_ip():
    if not check_auth():
         return jsonify({"error": "Unauthorized"}), 401
         
    data = request.json or {}
    ip = data.get('ip')
    if not ip:
         return jsonify({"error": "IP is required"}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": f"Invalid IP format: {ip}"}), 400

    logger.info(f"[ADMIN] [WHITELIST] Request to whitelist {ip}")
    
    # Unban just in case they were previously banned
    remove_ban(ip)
    BlockEvent.query.filter_by(ip=ip).delete()
    db.session.commit()
    
    # Add to runtime whitelist
    if 'WHITELIST' not in CONFIG:
        CONFIG['WHITELIST'] = []
    
    if ip not in CONFIG['WHITELIST']:
        CONFIG['WHITELIST'].append(ip)
        # Optional: Save back to config.json here if persistence is needed
        try:
           with open('config.json', 'w') as f:
               json.dump(CONFIG, f, indent=4)
        except Exception as e:
           logger.error(f"Could not persist config.json: {e}")
           
    return jsonify({"status": "whitelisted", "ip": ip, "whitelist": CONFIG['WHITELIST']})


 #Heartbeat
@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    # 1. Security Check (Added)
    # Previously missing in work_flow check phase 2!
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    sensor_id = data.get('sensor_id')
    if not sensor_id:
        return jsonify({"error": "sensor_id required"}), 400

    node = SensorNode.query.get(sensor_id)
    if not node:
        node = SensorNode(id=sensor_id, ip=request.remote_addr)
        db.session.add(node)

    node.last_seen = datetime.utcnow()
    node.status = data.get('status') or 'online'
    cpu_load = data.get('cpu_load')
    if isinstance(cpu_load, (int, float)):
        node.cpu_load = float(cpu_load)
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
             
        # Allow WHITELIST, BLOCK_THRESHOLD, TRUST_THRESHOLD updates from dashboard
        allowed_keys = ['WHITELIST', 'BLOCK_THRESHOLD', 'TRUST_THRESHOLD']
        
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

# --- DASHBOARD ROUTES ---
DASHBOARD_DIR = os.path.join(basedir, 'dashboard')

@app.route('/dashboard')
def serve_dashboard():
    """Serve the dashboard page with the API key injected from .env so it
    never has to be hardcoded in the client bundle."""
    with open(os.path.join(DASHBOARD_DIR, 'index.html'), encoding='utf-8') as f:
        html = f.read()
    html = html.replace('__NIDS_API_KEY__', CONFIG.get('API_KEY', ''))
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}

@app.route('/dashboard/<path:filename>')
def serve_dashboard_assets(filename):
    """Serve dashboard static assets (CSS, JS)"""
    return send_from_directory(DASHBOARD_DIR, filename, max_age=0)

# --- ADDITIONAL API ENDPOINTS ---

@app.route('/api/blocks', methods=['GET'])
def list_blocks():
    """List all active block events for the dashboard"""
    blocks = BlockEvent.query.order_by(BlockEvent.blocked_at.desc()).all()
    return jsonify([{
        "id": b.id,
        "ip": b.ip,
        "reason": b.reason,
        "blocked_at": b.blocked_at.isoformat() if b.blocked_at else None,
        "expires_at": b.expires_at.isoformat() if b.expires_at else None
    } for b in blocks])

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Read last N lines from audit.log for the terminal panel"""
    limit = max(1, min(request.args.get('limit', 40, type=int), 500))
    log_path = os.path.join(basedir, 'audit.log')
    lines = []
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
            lines = [l.strip() for l in all_lines[-limit:] if l.strip()]
    except FileNotFoundError:
        lines = ['No audit.log file found yet.']
    except Exception as e:
        lines = [f'Error reading logs: {str(e)}']
    return jsonify(lines)

@app.route('/api/verdicts', methods=['GET'])
def list_verdicts():
    """Last N verification verdicts — BLOCK, BORDERLINE, or UNVERIFIED.
    Optional query params: ?limit=50&verdict=BORDERLINE
    """
    limit = max(1, min(request.args.get('limit', 50, type=int), 500))
    verdict_filter = request.args.get('verdict', None)

    query = VerificationResult.query.order_by(VerificationResult.timestamp.desc())
    if verdict_filter:
        query = query.filter(VerificationResult.verdict == verdict_filter.upper())
    results = query.limit(limit).all()

    return jsonify([{
        "id":          r.id,
        "ip":          r.ip,
        "score":       r.score,
        "confidence":  r.confidence,
        "verdict":     r.verdict,
        "sensor_trust": r.sensor_trust,
        "sensors":     r.sensors,
        "timestamp":   r.timestamp.isoformat()
    } for r in results])

@app.route('/api/honeypot', methods=['GET'])
def list_honeypot_queue():
    """Returns unprocessed BORDERLINE IPs queued for honeypot verification."""
    entries = HoneypotQueue.query.filter_by(processed=False).order_by(
        HoneypotQueue.queued_at.desc()
    ).all()
    return jsonify([{
        "id":        e.id,
        "ip":        e.ip,
        "score":     e.score,
        "queued_at": e.queued_at.isoformat()
    } for e in entries])

# --- BACKGROUND MAINTENANCE THREAD ---
from datetime import timedelta
import time

# Honeypot follow-up window: borderline IPs are "evaluated" after this many
# seconds and the queue entry is marked processed. Real honeypot integration
# would replace this stub with an actual probe.
HONEYPOT_EVAL_SECONDS = 60

# Trust decay pulls each sensor's trust score 1% closer to the default (50)
# every hour. Without it, a sensor that was correct once stays trusted
# forever, and a sensor that was wrong once is penalised forever.
TRUST_DECAY_INTERVAL_SECONDS = 3600
TRUST_DEFAULT = 50.0
TRUST_DECAY_FACTOR = 0.01

_last_trust_decay = 0.0

def background_maintenance():
    """
    Runs every 15 seconds in a daemon thread:
      - Marks sensors as 'offline' if last_seen > 30 seconds ago.
      - Deletes expired BlockEvent records and lifts their firewall bans.
      - Stub-processes the HoneypotQueue: anything older than
        HONEYPOT_EVAL_SECONDS is marked processed.
      - Once per hour, applies a small trust decay to every sensor.
    """
    global _last_trust_decay
    while True:
        time.sleep(15)
        try:
            with app.app_context():
                now = datetime.utcnow()
                wall = time.time()

                cutoff = now - timedelta(seconds=30)
                stale_sensors = SensorNode.query.filter(
                    SensorNode.last_seen < cutoff,
                    SensorNode.status != "offline"
                ).all()
                for node in stale_sensors:
                    node.status = "offline"
                    logger.info(
                        f"[MAINTENANCE] Sensor {node.id} marked offline "
                        f"(last seen: {node.last_seen})"
                    )

                expired_blocks = BlockEvent.query.filter(
                    BlockEvent.expires_at != None,
                    BlockEvent.expires_at < now
                ).all()
                for block in expired_blocks:
                    logger.info(
                        f"[MAINTENANCE] Expired block removed: {block.ip} "
                        f"(expired at: {block.expires_at})"
                    )
                    remove_ban(block.ip)
                    db.session.delete(block)

                # Honeypot stub: borderline IPs that have been queued long
                # enough are marked processed. The verdict was inconclusive;
                # we're recording that we looked and moved on. A real
                # honeypot would write evidence back here.
                honeypot_cutoff = now - timedelta(seconds=HONEYPOT_EVAL_SECONDS)
                stale_honeypot = HoneypotQueue.query.filter(
                    HoneypotQueue.processed == False,
                    HoneypotQueue.queued_at < honeypot_cutoff
                ).all()
                for entry in stale_honeypot:
                    entry.processed = True
                    logger.info(
                        f"[HONEYPOT] {entry.ip} evaluated, no follow-up "
                        f"(score: {entry.score:.2f})"
                    )

                # Hourly trust decay
                if wall - _last_trust_decay >= TRUST_DECAY_INTERVAL_SECONDS:
                    _last_trust_decay = wall
                    sensors = SensorNode.query.all()
                    for node in sensors:
                        delta = (TRUST_DEFAULT - node.trust_score) * TRUST_DECAY_FACTOR
                        if abs(delta) >= 0.01:
                            node.trust_score = max(0.0, min(100.0, node.trust_score + delta))
                    if sensors:
                        logger.info(f"[MAINTENANCE] Trust decay applied to {len(sensors)} sensors")

                db.session.commit()
        except Exception as e:
            logger.error(f"[MAINTENANCE] Background task error: {e}")

# Start the maintenance thread as a daemon (auto-exits with the app)
maintenance_thread = threading.Thread(target=background_maintenance, daemon=True)
maintenance_thread.start()
logger.info("[MAINTENANCE] Background maintenance thread started (15s interval)")

if __name__ == '__main__':
    # Try SSL first; fall back to plain HTTP for dev/testing
    ssl_ctx = None
    cert_path = os.path.join(basedir, 'cert.pem')
    key_path = os.path.join(basedir, 'key.pem')
    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_ctx = (cert_path, key_path)
        logger.info("Starting with SSL (cert.pem + key.pem)")
    else:
        logger.warning("SSL certs not found — starting in HTTP-only dev mode")
    app.run(host='0.0.0.0', port=5000, threaded=True, ssl_context=ssl_ctx)