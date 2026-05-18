#!/bin/bash
#
# normal_traffic.sh — Ambient benign traffic generator for live demo.
#
# Runs continuously in a tmux pane during the presentation. Every ~10
# seconds it touches one of a small set of single-domain servers with
# DNS, HTTP, and ICMP. Provides a visible "normal traffic flow" baseline
# on the dashboard between attack demos — so the panel isn't dead-empty
# and the audience can SEE that legitimate traffic doesn't fire alerts.
#
# Each touched target is a single-domain, non-CDN server. We deliberately
# avoid Google/YouTube/Cloudflare CDNs because their edge-server roulette
# generates many brief connections to many IPs, which doesn't match the
# sustained-flow profile the model was trained on.
#
# Run from any non-whitelisted machine on the demo VLAN.
# Stop with Ctrl+C.

set -e

TARGETS=(
    "example.com"
    "example.org"
    "www.kernel.org"
    "en.wikipedia.org"
    "www.gnu.org"
    "www.iana.org"
)

echo "[normal_traffic] Starting ambient flow. Ctrl+C to stop."
echo "[normal_traffic] Targets: ${TARGETS[*]}"
echo

while true; do
    for t in "${TARGETS[@]}"; do
        # DNS lookup — matches `dns` training cluster
        dig @1.1.1.1 +short "$t" > /dev/null 2>&1 || true

        # Plain HTTP probe — matches `web_idle` cluster
        curl -s -o /dev/null -m 5 -w "[%{time_total}s] $t HTTP %{http_code}\n" \
            "http://$t/" 2>/dev/null || echo "[skip] $t HTTP"

        # Small ping flurry — matches `ping` cluster exactly
        ping -c 3 -W 1 "$t" > /dev/null 2>&1 || true

        sleep 8
    done
done
