import logging
import threading
from enforcement import enforce_block

logger = logging.getLogger("NIDS_Controller.Verification")

class VerificationEngine:
    def __init__(self, config):
        self.config = config
        self.history = {}       # {ip: {'cumulative_score': 0, 'hits': 0}}
        self.trust_scores = {}  # {sensor_id: score (0-100)}
        self.db_lock = threading.Lock()

    def process_threat(self, sensor_id, ip, raw_score):
        """
        Decides if a threat is real.
        """
        with self.db_lock:
            # 1. Initialize Trust if new sensor
            if sensor_id not in self.trust_scores:
                self.trust_scores[sensor_id] = 50 # Neutral start
            
            current_trust = self.trust_scores[sensor_id]
            
            # 2. Update History
            if ip not in self.history:
                self.history[ip] = {'cumulative_score': 0, 'hits': 0}
            
            # 3. Calculate Weighted Score
            # If we trust the sensor (100%), we take full score.
            # If we doubt the sensor (50%), we only take half the score.
            weighted_impact = raw_score * (current_trust / 100.0)
            
            self.history[ip]['cumulative_score'] += weighted_impact
            self.history[ip]['hits'] += 1
            
            total_threat = self.history[ip]['cumulative_score']
            
            logger.info(f"Analysis: IP={ip} | Threat={total_threat:.2f} | ReportedBy={sensor_id} (Trust: {current_trust})")

            # 4. The Verdict
            if total_threat > self.config['BLOCK_THRESHOLD']:
                enforce_block(ip, self.history[ip], self.config['WHITELIST'])
                # Reset score slightly to prevent re-blocking immediately if unblocked
                self.history[ip]['cumulative_score'] = 0 

    def get_trust_scores(self):
        with self.db_lock:
            return self.trust_scores.copy()
