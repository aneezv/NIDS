import logging
import threading
import json
import os
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
# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("NIDS_Controller")
# --- CORE ENGINE ---
engine = VerificationEngine(CONFIG)
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
    
    # 3. Check Score Type
    # Allow int or float, but reject strings/bools
    if not isinstance(data.get('score'), (int, float)):
        return False, "Score must be a number"
    return True, ""
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
@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    # 1. Security Check (Added)
    # Previously missing in work_flow check phase 2!
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    if not data or 'sensor_id' not in data:
        return jsonify({"error": "Missing sensor_id"}), 400
    
    # In a real app, update the 'last_seen' timestamp in DB
    logger.info(f"❤️ Heartbeat from {data['sensor_id']} (CPU: {data.get('cpu_load', '?')}%)")
    
    return jsonify({"status": "ok", "command": "continue"}), 200
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