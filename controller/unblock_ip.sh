#!/bin/bash
# Usage: ./unblock_ip.sh <IP_ADDRESS>

IP=$1

if [ -z "$IP" ]; then
    echo "Error: Please provide an IP address."
    exit 1
fi

# Remove IP from the blacklist set
ipset -exist del blacklist $IP 2>/dev/null

echo "Unblocked $IP."
