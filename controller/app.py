import logging
import threading
import json
import os
from enforce_auth import register_security
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
register_security(app)


# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("NIDS_Controller")

# --- CORE ENGINE ---
engine = VerificationEngine(CONFIG)

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

@app.route('/trust', methods=['GET'])
def get_trust():
    """Admin endpoint to view sensor health"""
    return jsonify(engine.get_trust_scores())

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    data = request.json
    if not data or 'sensor_id' not in data:
        return jsonify({"error": "Missing sensor_id"}), 400
    
    # In a real app, update the 'last_seen' timestamp in DB
    # For now, we will just log it.
    logger.info(f"❤️ Heartbeat from {data['sensor_id']} (CPU: {data.get('cpu_load', '?')}%)")
    
    # Create the response
    return jsonify({"status": "ok", "command": "continue"}), 200
    
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