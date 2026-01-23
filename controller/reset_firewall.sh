#!/bin/bash
echo "🧹 RESETTING FIREWALL..."

# Flush the blacklist (Unban everyone)
sudo ipset flush blacklist

# Clear iptables rules (Optional - cautious)
# sudo iptables -F
# sudo iptables -t nat -F

echo "✅ All bans lifted. Traffic is flowing."
