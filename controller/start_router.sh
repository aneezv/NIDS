#!/bin/bash

echo "🚀 STARTING NIDS CONTROLLER NODE (BRAIN & MUSCLE)..."

# --- 1. Network Configuration ---
echo "🔧 Configuring Network (Gateway Mode)..."
# Enable IP Forwarding
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Configure LAN Interface (Adjust 'eth1' to your internal interface name)
LAN_IF="eth1"
WAN_IF="eth0"

sudo ip addr flush dev $LAN_IF
sudo ip addr add 10.0.0.1/24 dev $LAN_IF
sudo ip link set $LAN_IF up

# Enable NAT (Masquerade) so Victim has Internet
sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE

# --- 2. Firewall Preparation ---
echo "🛡️  Initializing Firewall (ipset)..."
# Create the blacklist set if it doesn't exist
sudo ipset create blacklist hash:ip timeout 300 -exist
# Flush old rules to start fresh
sudo ipset flush blacklist
# Link ipset to iptables (Drop traffic from blacklisted IPs)
# Check if rule exists first to avoid duplicates
sudo iptables -C INPUT -m set --match-set blacklist src -j DROP 2>/dev/null
if [ $? -ne 0 ]; then
    sudo iptables -I INPUT -m set --match-set blacklist src -j DROP
    sudo iptables -I FORWARD -m set --match-set blacklist src -j DROP
fi

# --- 3. Start the Controller ---
echo "🧠 Starting Python Controller..."
# Check for SSL Certs
if [ ! -f "cert.pem" ]; then
    echo "⚠️  Generating Self-Signed SSL Certificates..."
    openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj "/C=XX/ST=State/L=City/O=NIDS/CN=10.0.0.1" 2>/dev/null
fi

# Run the app
sudo python3 app.py
