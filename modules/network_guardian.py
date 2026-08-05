import psutil, datetime

class NetworkGuardian:
    def __init__(self, db_conn):
        self.db = db_conn
        self.suspicious_ports = [1337, 4444, 5555, 6666, 8080, 9999]

    def scan_network(self):
        cursor = self.db.cursor()
        for conn in psutil.net_connections(kind="inet"):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?"
            if conn.raddr and conn.raddr.port in self.suspicious_ports:
                cursor.execute("INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                               (datetime.datetime.now().isoformat(), "network", f"{laddr}->{raddr}", conn.pid or -1))
                self.db.commit()
                print(f"[NET-THREAT] Suspicious {laddr} -> {raddr}")