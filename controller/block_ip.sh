#!/bin/bash
# Usage: ./block_ip.sh <IP_ADDRESS> <TIMEOUT_SECONDS>

IP=$1
TIMEOUT=$2

# Validate that we received a timeout, otherwise default to 300
if [ -z "$TIMEOUT" ]; then
    TIMEOUT=300
fi

# Add IP to the blacklist with the specific timeout
ipset -exist add blacklist $IP timeout $TIMEOUT

echo "Blocked $IP for $TIMEOUT seconds."
