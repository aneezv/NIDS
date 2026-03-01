#!/bin/bash
# Usage: ./tarpit_ip.sh <IP_ADDRESS>
# Rate-limits and slows TCP connections from attacker IP

IP=$1

if [ -z "$IP" ]; then
    echo "Error: Please provide an IP address."
    exit 1
fi

# Create a rate-limit rule for this IP
# Limit to 1 new connection per minute, burst of 2
iptables -I INPUT -s $IP -p tcp -m conntrack --ctstate NEW -m limit --limit 1/min --limit-burst 2 -j ACCEPT
iptables -A INPUT -s $IP -p tcp -m conntrack --ctstate NEW -j DROP

echo "Tarpitted $IP (rate-limited to 1 conn/min)."
