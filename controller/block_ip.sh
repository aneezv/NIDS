#!/bin/bash
# Usage: ./block_ip.sh <IP_ADDRESS> <TIMEOUT_SECONDS>

IP=$1
TIMEOUT=$2

# Validate that we received a timeout, otherwise default to 300
if [ -z "$TIMEOUT" ]; then
    TIMEOUT=300
fi

# Ensure the blacklist set exists (idempotent)
# Use -exist to avoid error if it already exists
ipset create blacklist hash:ip timeout 300 -exist 2>/dev/null

# Add IP to the blacklist with the specific timeout
ipset -exist add blacklist $IP timeout $TIMEOUT

echo "Blocked $IP for $TIMEOUT seconds."
