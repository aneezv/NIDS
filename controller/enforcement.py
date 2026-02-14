import logging
import subprocess

# Use child logger - inherits handlers from parent "NIDS_Controller"
logger = logging.getLogger("NIDS_Controller.Enforcement")

def calculate_ban_duration(ip,app):
    """
    Returns seconds to ban based on repeat offenses (previous blocks).
    """
    with app.app_context():
        from models import BlockEvent
        # Count how many times this IP has been blocked before
        offense_count = BlockEvent.query.filter_by(ip=ip).count()

    # offense_count is previous blocks.
    # 0 prev blocks = 1st offense
    # 1 prev block = 2nd offense

    if offense_count == 0:
        return 300      # 5 Minutes
    elif offense_count == 1:
        return 1800     # 30 Minutes
    else:
        return 86400    # 24 Hours (Maximum Penalty)

def enforce_block(ip, threat_info, whitelist, app):
    """Executes the actual firewall block using ipset/iptables"""
    if ip in whitelist:
        logger.warning(f"CRITICAL: Attempted to block Whitelisted IP {ip}. Action Aborted.")
        return

    # 1. Calculate Duration
    duration = calculate_ban_duration(ip,app)

    with app.app_context():
        from models import BlockEvent
        offense_count = BlockEvent.query.filter_by(ip=ip).count()

    logger.info(f"⚔️ BLOCKING {ip} for {duration} seconds (Offense #{offense_count + 1})")

    # 2. Pass duration to the script
    try:
        # Note: block_ip.sh must be in the same directory as the runner
        subprocess.run(["sudo", "./block_ip.sh", ip, str(duration)], check=True)
        #  logger.info(f"called block_ip.sh for {ip} for {duration} seconds")

    except Exception as e:
        logger.error(f"Failed to execute block: {e}")
