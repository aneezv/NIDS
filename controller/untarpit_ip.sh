#!/bin/bash
# Usage: ./untarpit_ip.sh <IP_ADDRESS>
# Removes rate-limiting rules for an IP

IP=$1

if [ -z "$IP" ]; then
    echo "Error: Please provide an IP address."
    exit 1
fi

# Remove the rate-limit and drop rules for this IP
iptables -D INPUT -s $IP -p tcp -m conntrack --ctstate NEW -m limit --limit 1/min --limit-burst 2 -j ACCEPT 2>/dev/null
iptables -D INPUT -s $IP -p tcp -m conntrack --ctstate NEW -j DROP 2>/dev/null

echo "Untarpitted $IP (rate-limit removed)."
