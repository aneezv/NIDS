#!/bin/bash

# REPLACE THIS WITH YOUR ROUTER'S EXTERNAL IP (Run 'ip a' on Router to find it)
ROUTER_IP="192.168.16.42" 

echo "⚔️  PREPARING ATTACK ROUTE..."

# Add route to reach the hidden 10.0.0.x network via the Router
sudo ip route add 10.0.0.0/24 via $ROUTER_IP 2>/dev/null

echo "✅ Route added. You can now attack 10.0.0.50"
echo "   Try: ping 10.0.0.50"
