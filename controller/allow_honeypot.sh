#!/bin/bash
# Usage: ./allow_honeypot.sh <IP_ADDRESS>
# Opens honeypot decoy ports ONLY for a specific attacker IP.
# Ports: 8443 (fake HTTPS), 2323 (fake Telnet), 8222 (fake SSH)

IP=$1
HONEYPOT_PORTS="8443,2323,8222"

if [ -z "$IP" ]; then
    echo "Error: Please provide an IP address."
    exit 1
fi

# Allow this specific IP to reach honeypot ports
iptables -I INPUT -s $IP -p tcp -m multiport --dports $HONEYPOT_PORTS -j ACCEPT

echo "Honeypot ports ($HONEYPOT_PORTS) opened for $IP."
