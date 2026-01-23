import logging
import subprocess

logger = logging.getLogger("NIDS_Controller.Enforcement")

def calculate_ban_duration(ip_history):
    """
    Returns seconds to ban based on repeat offenses.
    """
    offense_count = ip_history.get('hits', 0)
    
    if offense_count == 1:
        return 300      # 5 Minutes
    elif offense_count == 2:
        return 1800     # 30 Minutes
    elif offense_count >= 3:
        return 86400    # 24 Hours (Maximum Penalty)
    
    return 300 # Default

def enforce_block(ip, ip_history, whitelist):
    """Executes the actual firewall block using ipset/iptables"""
    if ip in whitelist:
        logger.warning(f"CRITICAL: Attempted to block Whitelisted IP {ip}. Action Aborted.")
        return

    # 1. Calculate Duration
    duration = calculate_ban_duration(ip_history)

    logger.info(f"⚔️ BLOCKING {ip} for {duration} seconds (Offense #{ip_history['hits']})")
    
    # 2. Pass duration to the script
    try:
        # Note: block_ip.sh must be in the same directory as the runner
        subprocess.run(["sudo", "./block_ip.sh", ip, str(duration)], check=True)
    except Exception as e:
        logger.error(f"Failed to execute block: {e}")
