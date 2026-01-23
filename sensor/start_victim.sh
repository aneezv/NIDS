#!/bin/bash

echo "🚀 STARTING NIDS SENSOR NODE (THE EYES)..."

# --- 1. Network Configuration ---
echo "🔧 Configuring Network (Client Mode)..."
IFACE="eth0" # Adjust to your interface

# Set Static IP
sudo ip addr flush dev $IFACE
sudo ip addr add 10.0.0.50/24 dev $IFACE
sudo ip link set $IFACE up

# Set Default Gateway (Point to Router)
sudo ip route add default via 10.0.0.1 2>/dev/null

# Fix DNS (The Google Ping Issue)
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null

# --- 2. Start the Sensor ---
echo "👀 Starting Python Sensor..."
# Check if model exists
if [ ! -f "model.pkl" ]; then
    echo "❌ ERROR: 'model.pkl' not found. Please run 'sudo python3 train.py' first!"
    exit 1
fi

sudo python3 sensor.py
