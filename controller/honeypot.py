"""
NIDS Honeypot Service (v5)
Always-on low-interaction honeypot with behavioral fingerprinting.
Runs decoy services on ports: 8443 (HTTPS), 2323 (Telnet), 8222 (SSH)

Usage: python honeypot.py
"""

import socket
import threading
import logging
import json
import ssl
import os
import sys
import re
import requests
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# --- CONFIGURATION ---
CONTROLLER_URL = os.getenv("CONTROLLER_URL", "https://127.0.0.1:5000")
API_KEY = os.getenv("API_KEY", "supersecretkey123")

HONEYPOT_PORTS = {
    8222: {"name": "SSH",    "banner": "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n"},
    2323: {"name": "Telnet", "banner": "\r\nUbuntu 18.04.6 LTS\r\nLogin: "},
    8443: {"name": "HTTPS",  "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\n\r\n<html><title>Admin Panel</title><body><h1>Authentication Required</h1></body></html>\r\n"},
}

# --- LOGGING ---
logger = logging.getLogger("NIDS_Honeypot")
logger.setLevel(logging.INFO)
logger.propagate = False

# File handler
file_handler = logging.FileHandler('honeypot.log', encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s - [%(name)s] %(message)s'))
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(console_handler)


# --- BEHAVIORAL FINGERPRINTING ---

def identify_tool(data, port):
    """
    Identifies attacker tooling from payload patterns.
    Returns: (tool_signature, technique)
    """
    data_str = data.decode('utf-8', errors='ignore').strip()

    # SSH probes
    if port == 8222:
        if data_str.startswith("SSH-"):
            # Extract client version
            return data_str.split('\r')[0], "banner_grab"
        if re.search(r'(password|pass|pwd)', data_str, re.IGNORECASE):
            return "brute_force_client", "brute_force"
        return "unknown_ssh_client", "ssh_probe"

    # Telnet probes
    if port == 2323:
        if re.search(r'(admin|root|user)', data_str, re.IGNORECASE):
            return "credential_stuffer", "brute_force"
        if re.search(r'(busybox|wget|curl|tftp)', data_str, re.IGNORECASE):
            return "iot_botnet", "command_injection"
        return "unknown_telnet_client", "telnet_probe"

    # HTTP probes
    if port == 8443:
        if 'nmap' in data_str.lower() or 'Nmap' in data_str:
            return "nmap_http_scanner", "service_scan"
        if 'nikto' in data_str.lower():
            return "nikto", "vuln_scan"
        if re.search(r'(sqlmap|union|select|insert|drop)', data_str, re.IGNORECASE):
            return "sql_injection_tool", "sql_injection"
        if re.search(r'(\.\.\/|\.\.\\|etc\/passwd|cmd\.exe)', data_str):
            return "directory_traversal_tool", "path_traversal"
        if 'GET' in data_str or 'POST' in data_str:
            return "http_client", "http_recon"
        return "unknown_http_client", "http_probe"

    return "unknown", "unknown"


# --- ALERT CALLBACK ---

def report_to_controller(attacker_ip, port, payload, tool_sig, technique):
    """
    Sends verified threat alert to the controller.
    Also sends a honeypot event log for historical correlation.
    """
    # 1. Send as a critical alert (score 100 = verified malicious)
    alert_payload = {
        "sensor_id": "HONEYPOT",
        "ip": attacker_ip,
        "score": 100
    }

    try:
        resp = requests.post(
            f"{CONTROLLER_URL}/alert",
            json=alert_payload,
            headers={"X-NIDS-Auth": API_KEY},
            verify=False,
            timeout=5
        )
        logger.info(f"[ALERT] Reported {attacker_ip} to controller (Status: {resp.status_code})")
    except Exception as e:
        logger.error(f"[ALERT] Failed to report to controller: {e}")

    # 2. Log honeypot event for historical DB
    event_payload = {
        "source_ip": attacker_ip,
        "port": port,
        "payload": payload[:500],  # Truncate large payloads
        "tool_sig": tool_sig,
        "technique": technique
    }

    try:
        resp = requests.post(
            f"{CONTROLLER_URL}/api/honeypot/event",
            json=event_payload,
            headers={"X-NIDS-Auth": API_KEY},
            verify=False,
            timeout=5
        )
        logger.info(f"[EVENT] Logged honeypot event for {attacker_ip} (Status: {resp.status_code})")
    except Exception as e:
        logger.error(f"[EVENT] Failed to log honeypot event: {e}")


# --- DECOY SERVICE HANDLER ---

def handle_connection(client_socket, client_addr, port_config, port):
    """
    Handle a single attacker connection on a decoy service.
    """
    attacker_ip = client_addr[0]
    attacker_port = client_addr[1]

    logger.info(f"🪤 [TRAPPED] {attacker_ip}:{attacker_port} connected to {port_config['name']} honeypot (port {port})")

    try:
        # Send the fake service banner
        client_socket.sendall(port_config['banner'].encode('utf-8'))

        # Wait for attacker's response (with timeout)
        client_socket.settimeout(30)
        try:
            data = client_socket.recv(4096)
            payload = data.decode('utf-8', errors='ignore')
            logger.info(f"📥 [DATA] From {attacker_ip}: {payload[:200]}")

            # Behavioral fingerprinting
            tool_sig, technique = identify_tool(data, port)
            logger.info(f"🔍 [FINGERPRINT] {attacker_ip}: tool={tool_sig}, technique={technique}")

            # For SSH: send fake password prompt to capture credentials
            if port == 8222 and 'SSH-' in payload:
                client_socket.sendall(b"Password: ")
                try:
                    cred_data = client_socket.recv(1024)
                    cred = cred_data.decode('utf-8', errors='ignore').strip()
                    logger.info(f"🔑 [CREDS] {attacker_ip} tried password: {cred}")
                    tool_sig = "brute_force_client"
                    technique = "brute_force"
                    payload += f" | password_attempt: {cred}"
                except socket.timeout:
                    pass

            # For Telnet: capture login attempts
            if port == 2323:
                client_socket.sendall(b"Password: ")
                try:
                    cred_data = client_socket.recv(1024)
                    cred = cred_data.decode('utf-8', errors='ignore').strip()
                    logger.info(f"🔑 [CREDS] {attacker_ip} tried: {payload.strip()}/{cred}")
                    payload += f" | password: {cred}"
                except socket.timeout:
                    pass

        except socket.timeout:
            payload = "(no data sent - connection only)"
            tool_sig = "scanner"
            technique = "port_scan"
            logger.info(f"⏱️ [TIMEOUT] {attacker_ip} connected but sent no data")

        # Report to controller
        report_to_controller(attacker_ip, port, payload, tool_sig, technique)

    except Exception as e:
        logger.error(f"Error handling {attacker_ip}: {e}")
    finally:
        client_socket.close()


# --- SERVICE LISTENER ---

def start_service(port, port_config):
    """
    Starts a TCP listener for one decoy service.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(('0.0.0.0', port))
        server.listen(5)
        logger.info(f"🎭 {port_config['name']} honeypot listening on port {port}")

        while True:
            try:
                client_socket, client_addr = server.accept()
                handler = threading.Thread(
                    target=handle_connection,
                    args=(client_socket, client_addr, port_config, port)
                )
                handler.daemon = True
                handler.start()
            except Exception as e:
                logger.error(f"Accept error on port {port}: {e}")

    except OSError as e:
        logger.error(f"❌ Cannot bind to port {port}: {e}")
    except Exception as e:
        logger.error(f"❌ Service error on port {port}: {e}")


# --- MAIN ---

def main():
    logger.info("=" * 60)
    logger.info("    NIDS Honeypot Service v5 Starting...")
    logger.info(f"    Controller: {CONTROLLER_URL}")
    logger.info(f"    Decoy Ports: {list(HONEYPOT_PORTS.keys())}")
    logger.info("=" * 60)

    threads = []
    for port, config in HONEYPOT_PORTS.items():
        t = threading.Thread(target=start_service, args=(port, config))
        t.daemon = True
        t.start()
        threads.append(t)

    # Keep main thread alive
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logger.info("Honeypot shutting down...")


if __name__ == '__main__':
    main()
