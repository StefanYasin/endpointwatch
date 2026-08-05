import numpy as np, datetime
from sklearn.ensemble import IsolationForest

class BehavioralAI:
    def __init__(self, db_conn):
        self.db = db_conn
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.trained = False

    def train_baseline(self, metrics_list):
        X = np.array([[m['cpu'], m['mem'], m['procs'], m['conns']] for m in metrics_list])
        self.model.fit(X)
        self.trained = True
        print("[AI] Baseline trained")

    def detect_anomaly(self, metrics):
        if not self.trained:
            return None
        X = np.array([[metrics['cpu'], metrics['mem'], metrics['procs'], metrics['conns']]])
        pred = self.model.predict(X)[0]
        score = self.model.decision_function(X)[0]
        if pred == -1:
            cursor = self.db.cursor()
            cursor.execute("INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                           (datetime.datetime.now().isoformat(), "anomaly", f"Score {score:.3f}", -1))
            self.db.commit()
            return {"anomaly": True, "score": score}
        return {"anomaly": False, "score": score}