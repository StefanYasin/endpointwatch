# modules/network_monitor.py
import psutil, datetime

class NetworkMonitor:
    def __init__(self, db_conn):
        self.db = db_conn
        # Example suspicious ports
        self.suspicious_ports = [4444, 1337, 6667, 3389]

    def scan_ports(self):
        threats = []
        cursor = self.db.cursor()
        for conn in psutil.net_connections(kind="inet"):
            try:
                laddr = conn.laddr.port if conn.laddr else None
                pid = conn.pid
                if laddr in self.suspicious_ports:
                    cursor.execute(
                        "INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                        (datetime.datetime.now().isoformat(),
                         "network",
                         f"Port {laddr}",
                         pid or -1)
                    )
                    self.db.commit()
                    threats.append({"port": laddr, "pid": pid})
            except Exception:
                continue
        return threats