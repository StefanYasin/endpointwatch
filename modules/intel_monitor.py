# modules/intel_monitor.py
import requests, datetime

class IntelMonitor:
    def __init__(self, db_conn):
        self.db = db_conn
        self.apikeys = {}
        try:
            from config import load_api_keys
            self.apikeys = load_api_keys()
        except Exception:
            pass

    def check_abuseipdb(self, ip):
        key = self.apikeys.get("abuseipdb")
        if not key:
            return None
        url = "https://api.abuseipdb.com/api/v2/check"
        try:
            r = requests.get(url, params={"ipAddress": ip, "maxAgeInDays": 90},
                             headers={"Key": key, "Accept": "application/json"}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                return data["data"]["abuseConfidenceScore"]
        except Exception:
            return None
        return None

    def scan_ip(self, ip):
        threats = []
        score = self.check_abuseipdb(ip)
        if score and score > 50:
            cursor = self.db.cursor()
            msg = f"IP {ip} flagged with AbuseIPDB score {score}"
            cursor.execute(
                "INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                (datetime.datetime.now().isoformat(), "intel", msg, -1)
            )
            self.db.commit()
            threats.append(msg)
        return threats