import subprocess
import requests
import time
import os
import urllib3
import json
from features import parse_tshark_line
from detector import AnomalyDetector

# --- CONFIGURATION ---
with open("config.json") as config :
    data = json.load(config)
    
CONTROLLER_URL = data.get("controller_url")
API_KEY = data.get("api_key")
INTERFACE = data.get("interface")
BATCH_SIZE = data.get("batch_size")
SENSOR_ID = data.get("sensor_id")
MODEL_PATH = data.get("model_path")
THRESHOLD = data.get("threshold")
WHITELIST = data.get("whitelist", ["127.0.0.1"])
CERT_PATH = data.get("cert_path", "cert.pem") # Path to the certificate copied from controller

# --- INITIALIZATION ---
detector = AnomalyDetector(
    model_path = MODEL_PATH,
    threshold = THRESHOLD
)
last_alert_time = {} 

# Silence SSL Warnings only if we are forced to use verify=False
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def send_alert(ip, score):
    try:
        payload = {
            "sensor_id": SENSOR_ID,
            "ip": ip,
            "score": score
        }
        
        # SSL Verification Logic
        verify_param = False
        if os.path.exists(CERT_PATH):
            verify_param = CERT_PATH
            # Note: If you get a "Hostname Mismatch", it's because the cert 
            # was issued for 'localhost' or another name, not the IP.
        
        requests.post(
            CONTROLLER_URL, 
            json=payload, 
            headers={"X-NIDS-Auth": API_KEY}, 
            verify=verify_param, 
            timeout=1
        )
        print(f"🚀 Alert Sent: {ip} (Conf: {score:.1f})")
    except requests.exceptions.SSLError as e:
        print(f"🔒 SSL Error: {e}")
        print("💡 Tip: If you see 'Hostname Mismatch', the certificate doesn't match the Controller IP.")
        print("   For this demo, you can temporarily revert verify=False in sensor.py if needed.")
    except Exception as e:
        print(f"❌ Controller Error: {e}")

def monitor_traffic():
    cmd = [
        "tshark", "-i", INTERFACE,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "frame.len",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "ip.proto",
        "-e", "tcp.flags",
        "-E", "separator=,",
        "-l"
    ]
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"👀 Sensor Active on {INTERFACE}...")
        
        batch_data = []
        batch_ips = []
        
        for line in process.stdout:
            src_ip, features = parse_tshark_line(line)
            
            if not features:
                continue

            # Whitelist Self/Router to avoid feedback loops
            if src_ip in WHITELIST: 
                continue

            batch_data.append(features)
            batch_ips.append(src_ip)
            
            if len(batch_data) >= BATCH_SIZE:
                results = detector.predict_batch(batch_data)
                
                for i, (raw_score, conf) in enumerate(results):
                    if conf > 20:
                        ip = batch_ips[i]
                        now = time.time()
                        
                        # Rate Limit (30s) per IP
                        if ip in last_alert_time and (now - last_alert_time[ip] < 30):
                            continue
                        
                        print(f"🚨 Anomaly Detected: {ip} | Score: {raw_score:.4f} | Conf: {conf:.1f}")
                        send_alert(ip, conf)
                        last_alert_time[ip] = now
                
                batch_data = []
                batch_ips = []

    except Exception as e:
        print(f"💥 Sensor Crash: {e}")

if __name__ == "__main__":
    monitor_traffic()
