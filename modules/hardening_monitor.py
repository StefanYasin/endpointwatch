# modules/hardening_monitor.py
import subprocess, ctypes, datetime, os

class HardeningMonitor:
    def __init__(self, db_conn):
        self.db = db_conn

    def check_defender(self):
        try:
            result = subprocess.run(["sc", "query", "WinDefend"],
                                    capture_output=True, text=True)
            return "RUNNING" in result.stdout.upper()
        except Exception:
            return False

    def check_firewall(self):
        try:
            result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                                    capture_output=True, text=True)
            return "ON" in result.stdout.upper()
        except Exception:
            return False

    def check_uac(self):
        try:
            key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                val, _ = winreg.QueryValueEx(k, "EnableLUA")
                return val == 1
        except Exception:
            return False

    def check_admins(self):
        try:
            result = subprocess.run(["net", "localgroup", "administrators"],
                                    capture_output=True, text=True)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    def scan_hardening(self):
        threats = []
        cursor = self.db.cursor()
        now = datetime.datetime.now().isoformat()

        defender = self.check_defender()
        firewall = self.check_firewall()
        uac = self.check_uac()
        admins = self.check_admins()

        if not defender:
            threats.append("Windows Defender disabled")
        if not firewall:
            threats.append("Firewall disabled")
        if not uac:
            threats.append("UAC disabled")
        if len(admins) > 2:  # usually Administrator + your account
            threats.append(f"Extra admins: {admins}")

        for t in threats:
            cursor.execute(
                "INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                (now, "hardening", t, -1)
            )
            self.db.commit()

        return threats# modules/hardening_monitor.py
import subprocess, ctypes, datetime, os

class HardeningMonitor:
    def __init__(self, db_conn):
        self.db = db_conn

    def check_defender(self):
        try:
            result = subprocess.run(["sc", "query", "WinDefend"],
                                    capture_output=True, text=True)
            return "RUNNING" in result.stdout.upper()
        except Exception:
            return False

    def check_firewall(self):
        try:
            result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                                    capture_output=True, text=True)
            return "ON" in result.stdout.upper()
        except Exception:
            return False

    def check_uac(self):
        try:
            key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                val, _ = winreg.QueryValueEx(k, "EnableLUA")
                return val == 1
        except Exception:
            return False

    def check_admins(self):
        try:
            result = subprocess.run(["net", "localgroup", "administrators"],
                                    capture_output=True, text=True)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    def scan_hardening(self):
        threats = []
        cursor = self.db.cursor()
        now = datetime.datetime.now().isoformat()

        defender = self.check_defender()
        firewall = self.check_firewall()
        uac = self.check_uac()
        admins = self.check_admins()

        if not defender:
            threats.append("Windows Defender disabled")
        if not firewall:
            threats.append("Firewall disabled")
        if not uac:
            threats.append("UAC disabled")
        if len(admins) > 2:  # usually Administrator + your account
            threats.append(f"Extra admins: {admins}")

        for t in threats:
            cursor.execute(
                "INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                (now, "hardening", t, -1)
            )
            self.db.commit()

        return threats