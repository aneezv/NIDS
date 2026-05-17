import logging
import subprocess

# Use child logger - inherits handlers from parent "NIDS_Controller"
logger = logging.getLogger("NIDS_Controller.Enforcement")

def calculate_ban_duration(ip, app):
    """
    Returns seconds to ban based on repeat offenses in the last 7 days.

    Only recent offenses count — a block from months ago shouldn't escalate
    today's IP straight to a 24h ban. The 7-day window resets after a week
    of good behaviour.
    """
    from datetime import datetime, timedelta
    from models import BlockEvent

    recent_cutoff = datetime.utcnow() - timedelta(days=7)
    offense_count = BlockEvent.query.filter(
        BlockEvent.ip == ip,
        BlockEvent.blocked_at >= recent_cutoff
    ).count()

    if offense_count == 0:
        return 300      # 5 minutes
    elif offense_count == 1:
        return 1800     # 30 minutes
    else:
        return 86400    # 24 hours (maximum penalty)

def enforce_block(ip, threat_info, whitelist, app, duration=None):
    """Executes the actual firewall block using ipset/iptables"""
    if ip in whitelist:
        logger.warning(f"CRITICAL: Attempted to block Whitelisted IP {ip}. Action Aborted.")
        return None

    # 1. Calculate Duration if not specified
    if duration is None:
        duration = calculate_ban_duration(ip, app)

    from models import BlockEvent
    offense_count = BlockEvent.query.filter_by(ip=ip).count()

    logger.info(f"⚔️ BLOCKING {ip} for {duration if duration > 0 else 'permanent'} seconds (Offense #{offense_count + 1})")

    # 2. Pass duration to the script
    try:
        # Note: block_ip.sh must be in the same directory as the runner
        subprocess.run(["sudo", "./block_ip.sh", ip, str(duration)], check=True)
    except Exception as e:
        logger.error(f"Failed to execute block: {e}")
        
    return duration

def remove_ban(ip):
    """Executes the actual firewall unblock using ipset/iptables"""
    logger.info(f"🛡️ UNBLOCKING {ip} manually")
    
    try:
        subprocess.run(["sudo", "./unblock_ip.sh", ip], check=True)
        logger.info(f"Successfully called unblock_ip.sh for {ip}")
    except Exception as e:
        logger.error(f"Failed to execute unblock: {e}")
