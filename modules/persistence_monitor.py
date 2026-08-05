# modules/persistence_monitor.py
import winreg, os, datetime, subprocess

class PersistenceMonitor:
    def __init__(self, db_conn):
        self.db = db_conn
        self.known = set()  # Track known persistence items

    def check_registry_run(self):
        items = []
        paths = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        ]
        for root in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            for path in paths:
                try:
                    key = winreg.OpenKey(root, path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            entry = f"{path}:{name}={value}"
                            items.append(entry)
                            i += 1
                        except OSError:
                            break
                except OSError:
                    continue
        return items

    def check_startup_folder(self):
        items = []
        folders = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp")
        ]
        for folder in folders:
            if os.path.exists(folder):
                for f in os.listdir(folder):
                    items.append(os.path.join(folder, f))
        return items

    def check_scheduled_tasks(self):
        items = []
        try:
            result = subprocess.run(["schtasks", "/query", "/fo", "LIST", "/v"],
                                    capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines():
                if line.startswith("TaskName:"):
                    items.append(line.strip())
        except Exception:
            pass
        return items

    def scan_persistence(self):
        threats = []
        cursor = self.db.cursor()
        now = datetime.datetime.now().isoformat()

        all_items = []
        all_items.extend(self.check_registry_run())
        all_items.extend(self.check_startup_folder())
        all_items.extend(self.check_scheduled_tasks())

        for item in all_items:
            if item not in self.known:
                cursor.execute(
                    "INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                    (now, "persistence", item, -1)
                )
                self.db.commit()
                threats.append(item)
                self.known.add(item)

        return threats