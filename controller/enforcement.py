import logging
import subprocess

# Use child logger - inherits handlers from parent "NIDS_Controller"
logger = logging.getLogger("NIDS_Controller.Enforcement")

def calculate_ban_duration(ip,app):
    """
    Returns seconds to ban based on repeat offenses.
    """
    with app.app_context():
        from models import Alert
        offense_count = Alert.query.filter_by(source_ip = ip).count()
    
    if offense_count == 1:
        return 300      # 5 Minutes
    elif offense_count == 2:
        return 1800     # 30 Minutes
    elif offense_count >= 3:
        return 86400    # 24 Hours (Maximum Penalty)
    
    return 300 # Default

def enforce_block(ip, threat_info, whitelist, app):
    """Executes the actual firewall block using ipset/iptables"""
    if ip in whitelist:
        logger.warning(f"CRITICAL: Attempted to block Whitelisted IP {ip}. Action Aborted.")
        return

    # 1. Calculate Duration
    duration = calculate_ban_duration(ip,app)

    with app.app_context():
        from models import Alert
        offense_count = Alert.query.filter_by(source_ip = ip).count()
        
    logger.info(f"⚔️ BLOCKING {ip} for {duration} seconds (Offense #{offense_count})")

    # 2. Pass duration to the script
    try:
        # Note: block_ip.sh must be in the same directory as the runner
        subprocess.run(["sudo", "./block_ip.sh", ip, str(duration)], check=True)
        #  logger.info(f"called block_ip.sh for {ip} for {duration} seconds")

    except Exception as e:
        logger.error(f"Failed to execute block: {e}")
