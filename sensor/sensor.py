import subprocess
import requests
import time
import os
import urllib3
import json
import threading
import psutil
import socket
import urllib.parse
import threading
import psutil
from collections import deque
from dotenv import load_dotenv
from features import parse_tshark_line
from detector import AnomalyDetector
import builtins

# --- LOGGING SETUP ---
_original_print = builtins.print
def _timestamped_print(*args, **kwargs):
    _original_print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}]", *args, **kwargs)
builtins.print = _timestamped_print

# --- CONFIGURATION ---
with open("config.json") as config :
    data = json.load(config)

if os.getenv("API_KEY"):
    data["API_KEY"] = os.getenv("API_KEY") 
  
CONTROLLER_URL = data.get("controller_url")
#create a heartbeat url to replace 'alert' with 'heartbeat'
HEARTBEAT_URL = CONTROLLER_URL.replace("alert","heartbeat")
API_KEY = data.get("API_KEY")
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
QUEUE=deque()

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

    except requests.RequestException:
        QUEUE.append(payload)
        print(f"❌ Controller Down , Queueing the alerts! {ip}")
    except Exception as e:
        print(f"❌ Controller Error: {e}")

def retry_worker():
    verify_param = False
    if os.path.exists(CERT_PATH):
            verify_param = CERT_PATH
    while True:
        if QUEUE:
            payload = QUEUE[0]
            try:
                r=requests.post(
                    CONTROLLER_URL, 
                    json=payload, 
                    headers={"X-NIDS-Auth": API_KEY}, 
                    verify=verify_param, 
                    timeout=1
                )
                r.raise_for_status()
                print(f"🚀 Queue Alert Sent: {payload["ip"]} (Conf: {payload["score"]:.1f})")
                QUEUE.popleft()
            except requests.RequestException:
                pass # controller still down
        time.sleep(2)

def send_heartbeat():
    """
    Runs in a background thread. Sends a heartbeat to the controller every 30s.
    """
    while True:
        try:

            CPU_LOAD = psutil.cpu_percent(interval=None)

            # Create the small JSON payload
            payload = {
                "sensor_id": SENSOR_ID,
                "status": "OK",
                "cpu_load": CPU_LOAD
            }
            
            # SSL Logic (same as send_alert)
            verify_param = False
            if os.path.exists(CERT_PATH):
                verify_param = CERT_PATH

            # Send the request
            requests.post(
                HEARTBEAT_URL, 
                json=payload, 
                headers={"X-NIDS-Auth": API_KEY}, 
                verify=verify_param, 
                timeout=2
            )
            # Optional: Print to console for debugging (can remove later)
            print(f"💓 Heartbeat sent to {HEARTBEAT_URL}")
            
        except Exception as e:
            # If it fails, just print a small error, don't crash
            print(f"⚠️ Heartbeat failed: {e}")
        
        time.sleep(30)

def hot_reload(new_path):
    """
    Reloads the Isolation Forest model at runtime.
    Can be called manually or by the watcher thread.
    """
    try:
        detector.load_model(new_path)
        print(f"🔄 Model reloaded: {os.path.basename(new_path)}")
    except Exception as e:
        print(f"⚠️ Hot reload failed: {e}")


def model_watcher():
    """
    Background thread: checks every 5 minutes if model_latest.pkl
    is newer than the currently loaded model. If yes, reloads it.
    """
    watch_path = os.path.join(os.path.dirname(MODEL_PATH), "model_latest.pkl")
    last_mtime = None

    while True:
        try:
            if os.path.exists(watch_path):
                current_mtime = os.path.getmtime(watch_path)
                if last_mtime is None or current_mtime > last_mtime:
                    print(f"🔍 New model detected: model_latest.pkl")
                    hot_reload(watch_path)
                    last_mtime = current_mtime
        except Exception as e:
            print(f"⚠️ Model watcher error: {e}")

        time.sleep(300)  # Check every 5 minutes

def monitor_traffic():
    # Attempt to determine sensor IP (default to 127.0.0.1 on failure)
    sensor_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        sensor_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    # Attempt to determine controller IP and Port
    controller_ip = "127.0.0.1"
    controller_port = 5000
    try:
        parsed = urllib.parse.urlparse(CONTROLLER_URL)
        if parsed.hostname:
            controller_ip = socket.gethostbyname(parsed.hostname)
        if parsed.port:
            controller_port = parsed.port
        elif parsed.scheme == "https":
            controller_port = 443
        elif parsed.scheme == "http":
            controller_port = 80
    except Exception:
        pass

    # BPF filter drops packets to/from the controller API to prevent alert feedback loops.
    # By using 'and port', attacks originating from the controller machine are still detected!
    bpf_filter = f"not (host {controller_ip} and port {controller_port})"
    print(f"🌍 Resolved Sensor IP: {sensor_ip} | Controller: {controller_ip}:{controller_port}")

    cmd = [
        "tshark", "-i", INTERFACE,
        "-f", bpf_filter,
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
        
        # [NEW] Micro-Flow State Tracker
        flow_state = {} # ip -> {'first_seen': float, 'pkts': int, 'bytes': int}
        WINDOW_SIZE = 2.0
        
        for line in process.stdout:
            src_ip, features = parse_tshark_line(line)
            
            if not features:
                continue

            # Whitelist Self/Router to avoid feedback loops
            if src_ip in WHITELIST: 
                continue
                
            now = time.time()
            frame_len = features[0]
            
            # [NEW] Flow logic update
            if src_ip not in flow_state:
                flow_state[src_ip] = {'first_seen': now, 'pkts': 0, 'bytes': 0}
                
            state = flow_state[src_ip]
            state['pkts'] += 1
            state['bytes'] += frame_len
            
            elapsed = now - state['first_seen']
            
            # Calculate rates. Force a minimum of 1.0s elapsed to prevent initial microsecond spikes.
            effective_elapsed = max(elapsed, 1.0)
            packet_rate = state['pkts'] / effective_elapsed
            byte_rate = state['bytes'] / effective_elapsed
            
            # Reset window every 2 seconds
            if elapsed >= WINDOW_SIZE:
                state['first_seen'] = now
                state['pkts'] = 0
                state['bytes'] = 0
                
            # Append new flow features to packet features
            # Old features: [frame_len, port, proto, flags]
            # New features: [frame_len, port, proto, flags, packet_rate, byte_rate]
            features.extend([packet_rate, byte_rate])

            batch_data.append(features)
            batch_ips.append(src_ip)
            
            if len(batch_data) >= BATCH_SIZE:
                results = detector.predict_batch(batch_data)
                
                for i, (raw_score, conf) in enumerate(results):
                    if conf > 20:
                        ip = batch_ips[i]
                        now_alert = time.time()
                        
                        # Rate Limit (8.5s) per IP for demonstration
                        if ip in last_alert_time and (now_alert - last_alert_time[ip] < 8.5):
                            continue
                        
                        print(f"🚨 Anomaly Detected: {ip} | Score: {raw_score:.4f} | Conf: {conf:.1f}")
                        send_alert(ip, conf)
                        last_alert_time[ip] = now_alert
                
                batch_data = []
                batch_ips = []

    except Exception as e:
        print(f"💥 Sensor Crash: {e}")

if __name__ == "__main__":
    heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
    retry_thread = threading.Thread(target=retry_worker, daemon=True)
    watcher_thread = threading.Thread(target=model_watcher, daemon=True)

    heartbeat_thread.start()
    retry_thread.start()
    watcher_thread.start()

    monitor_traffic()
