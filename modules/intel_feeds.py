import requests, json, os

class IntelFeeds:
    def __init__(self, keys_path="config/api_keys.json"):
        self.vt_key = None
        self.abuse_key = None
        if os.path.exists(keys_path):
            try:
                with open(keys_path) as f:
                    keys = json.load(f)
                    self.vt_key = keys.get("virustotal")
                    self.abuse_key = keys.get("abuseipdb")
            except Exception:
                pass

    def vt_lookup_file(self, filepath_or_hash):
        if not self.vt_key:
            return None
        url = f"https://www.virustotal.com/api/v3/files/{filepath_or_hash}"
        headers = {"x-apikey": self.vt_key}
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return f"VT: {stats}"
            return f"VT Error: {r.status_code}"
        except Exception as e:
            return f"VT Error: {e}"

    def abuse_lookup_ip(self, ip):
        if not self.abuse_key:
            return None
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuse_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        try:
            r = requests.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                data = r.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return f"AbuseIPDB: Score {score}"
            return f"AbuseIPDB Error: {r.status_code}"
        except Exception as e:
            return f"AbuseIPDB Error: {e}"