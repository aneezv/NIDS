#!/bin/bash
#
# Adds a route to the hidden 10.0.0.0/24 victim network via the router.
#
# Resolution order for the router IP:
#   1. First positional argument:   ./prepare_attack.sh 192.168.1.10
#   2. ROUTER_IP environment var:   ROUTER_IP=192.168.1.10 ./prepare_attack.sh
#   3. Built-in default below       (only valid on the original lab setup)

ROUTER_IP="${1:-${ROUTER_IP:-192.168.16.42}}"

if [[ -z "$ROUTER_IP" ]]; then
    echo "ERROR: ROUTER_IP not set. Pass as an argument or export ROUTER_IP." >&2
    exit 1
fi

echo "[*] PREPARING ATTACK ROUTE via $ROUTER_IP ..."
sudo ip route add 10.0.0.0/24 via "$ROUTER_IP" 2>/dev/null

echo "[+] Route added. You can now attack 10.0.0.50"
echo "    Try: ping 10.0.0.50"
