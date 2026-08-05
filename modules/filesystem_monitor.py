# modules/filesystem_monitor.py
import os, time, datetime, hashlib

class FileSystemMonitor:
    def __init__(self, db_conn):
        self.db = db_conn
        self.paths = [
            os.path.expandvars(r"%APPDATA%"),
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%SystemRoot%\System32")
        ]
        self.known = {}

    def sha256_of_file(self, path):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def scan_files(self):
        threats = []
        cursor = self.db.cursor()
        now = datetime.datetime.now().isoformat()

        for folder in self.paths:
            if not os.path.exists(folder):
                continue
            for root, dirs, files in os.walk(folder):
                for f in files:
                    if f.lower().endswith((".exe", ".dll")):
                        path = os.path.join(root, f)
                        sha = self.sha256_of_file(path)
                        key = f"{path}:{sha}"

                        if key not in self.known:
                            cursor.execute(
                                "INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                                (now, "filesystem", path, -1)
                            )
                            self.db.commit()
                            threats.append(path)
                            self.known[key] = True
        return threats