# core/correlation_engine.py

import datetime

class CorrelationEngine:
    def __init__(self, db_conn, gui, audio):
        self.db = db_conn
        self.gui = gui
        self.audio = audio

    def analyze(self, new_events):
        """
        Input: list of dicts like {"type": "process"/"network"/"clipboard", "msg": "..."}
        Output: logs correlated alerts if patterns match
        """
        types = {e["type"] for e in new_events}

        # Example correlation: process + network + clipboard
        if {"process", "network", "clipboard"}.issubset(types):
            msg = "⚠️ Multi-vector attack: suspicious process + network + clipboard hijack"
            self.log_correlation(msg)

        # Example correlation: process + network
        elif {"process", "network"}.issubset(types):
            msg = "⚠️ Process with suspicious network activity"
            self.log_correlation(msg)

        # Example: clipboard + network
        elif {"clipboard", "network"}.issubset(types):
            msg = "⚠️ Clipboard hijack with outbound connection"
            self.log_correlation(msg)

    def log_correlation(self, message):
        cursor = self.db.cursor()
        cursor.execute(
            "INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
            (datetime.datetime.now().isoformat(), "correlated", message, -1)
        )
        self.db.commit()
        self.gui.log_threat(message, category="correlated")
        self.audio.play("alert")
        self.gui.update_status("⚠️ Correlated threat detected!", color="magenta")