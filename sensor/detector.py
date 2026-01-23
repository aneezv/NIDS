import joblib
import pandas as pd

class AnomalyDetector:
    def __init__(self, model_path="model.pkl"):
        print(f"🧠 Loading Model from {model_path}...")
        self.model = joblib.load(model_path)
        self.feature_cols = ['frame.len', 'port', 'ip.proto', 'tcp.flags']

    def normalize_score(self, anomaly_score):
        """
        Converts Isolation Forest decision_function output to a 0-100 confidence score.
        IF returns negative for anomalies, positive for normal.
        """
        # Isolation Forest decision_function: 
        # Typically < 0 is anomaly, > 0 is normal.
        # User's logic: if score > 0.10 return 0 (Normal)
        # Else: min((0.10 - score) * 2000, 100)
        if anomaly_score > 0.10: 
            return 0.0
        return min((0.10 - anomaly_score) * 2000, 100)

    def predict_batch(self, batch_features):
        """
        batch_features: List of lists [frame_len, port, proto, flags]
        Returns: List of (raw_score, normalized_confidence)
        """
        df = pd.DataFrame(batch_features, columns=self.feature_cols)
        raw_scores = self.model.decision_function(df)
        
        results = []
        for score in raw_scores:
            results.append((score, self.normalize_score(score)))
        return results
