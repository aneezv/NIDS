import logging
import threading
import json
import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from verification import VerificationEngine

load_dotenv

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

# --- API ENDPOINTS ---

@app.route('/alert', methods=['POST'])
def receive_alert():
    """
    Sensor sends: { "sensor_id": "node1", "ip": "1.2.3.4", "score": 85 }
    """
    # 1. Security Check (API Key)
    api_key = request.headers.get('X-NIDS-Auth')
    if api_key != CONFIG['API_KEY']:
        return jsonify({"error": "Unauthorized"}), 401

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

if __name__ == '__main__':
    # Make sure cert.pem and key.pem are in the same folder!
    try:
        app.run(host='0.0.0.0', port=5000, threaded=True, ssl_context=('cert.pem', 'key.pem'))
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        logger.info("Falling back to HTTP (Non-secure) for debugging purposes.")
        app.run(host='0.0.0.0', port=5000, threaded=True)
