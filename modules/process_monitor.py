# modules/process_monitor.py

import psutil, datetime, os, hashlib, json, requests

class ProcessMonitor:
    def __init__(self, db_conn, config_path="config/process_config.json"):
        self.db = db_conn
        self.config_path = config_path
        self.whitelist, self.blacklist = self.load_config()
        self.seen = set()  # Track logged PIDs to avoid spam

        # VirusTotal API key (optional, set in config)
        self.vt_api_key = None
        if os.path.exists("config/api_keys.json"):
            try:
                with open("config/api_keys.json") as f:
                    keys = json.load(f)
                self.vt_api_key = keys.get("virustotal")
            except Exception:
                pass

    # ---------------- CONFIG ----------------
    def load_config(self):
        """Load whitelist/blacklist from config file"""
        default = {
            "whitelist": ["system", "idle", "secure system", "csrss.exe", "wininit.exe"],
            "blacklist": ["mimikatz.exe", "netcat.exe"]
        }
        if not os.path.exists(self.config_path):
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w") as f:
                json.dump(default, f, indent=2)
            return set(default["whitelist"]), set(default["blacklist"])

        try:
            with open(self.config_path) as f:
                cfg = json.load(f)
            return set(cfg.get("whitelist", [])), set(cfg.get("blacklist", []))
        except Exception:
            return set(default["whitelist"]), set(default["blacklist"])

    # ---------------- HASHING ----------------
    def sha256_of_file(self, path):
        """Compute SHA256 hash of a file safely"""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    # ---------------- VIRUSTOTAL ----------------
    def check_virustotal(self, sha256):
        """Check VirusTotal for hash reputation (if API key is set)"""
        if not self.vt_api_key or not sha256:
            return None
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": self.vt_api_key}
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return stats  # dict with harmless/malicious/suspicious counts
        except Exception:
            return None
        return None

    # ---------------- MAIN SCAN ----------------
    def scan_processes(self):
        threats = []
        cursor = self.db.cursor()

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = (proc.info['name'] or "").lower()
                exe = proc.info.get('exe') or ""

                # Skip system/whitelisted
                if name in self.whitelist:
                    continue

                # Blacklisted by name
                if name in self.blacklist and pid not in self.seen:
                    cursor.execute(
                        "INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                        (datetime.datetime.now().isoformat(), "process", name, pid)
                    )
                    self.db.commit()
                    threats.append({"name": name, "pid": pid})
                    self.seen.add(pid)
                    continue

                # Otherwise, calculate hash + check VT
                sha = self.sha256_of_file(exe)
                vt_result = self.check_virustotal(sha)

                # Flag if VirusTotal shows detections
                if vt_result and vt_result.get("malicious", 0) > 0 and pid not in self.seen:
                    msg = f"{name} flagged {vt_result['malicious']} engines"
                    cursor.execute(
                        "INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                        (datetime.datetime.now().isoformat(), "process", msg, pid)
                    )
                    self.db.commit()
                    threats.append({"name": name, "pid": pid})
                    self.seen.add(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        return threats