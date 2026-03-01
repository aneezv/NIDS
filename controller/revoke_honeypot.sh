#!/bin/bash
# Usage: ./revoke_honeypot.sh <IP_ADDRESS>
# Removes honeypot access rules for an IP (cleanup after block or TTL expiry).

IP=$1
HONEYPOT_PORTS="8443,2323,8222"

if [ -z "$IP" ]; then
    echo "Error: Please provide an IP address."
    exit 1
fi

# Remove the per-IP honeypot access rule
iptables -D INPUT -s $IP -p tcp -m multiport --dports $HONEYPOT_PORTS -j ACCEPT 2>/dev/null

echo "Honeypot access revoked for $IP."
