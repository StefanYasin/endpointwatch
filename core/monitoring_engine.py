# core/monitoring_engine.py

import threading, time
from modules.process_monitor import ProcessMonitor
from modules.network_monitor import NetworkMonitor
from modules.clipboard_guard import ClipboardGuard
from modules.persistence_monitor import PersistenceMonitor
from modules.filesystem_monitor import FileSystemMonitor
from modules.hardening_monitor import HardeningMonitor
from modules.intel_monitor import IntelMonitor
from core.correlation_engine import CorrelationEngine

class MonitoringEngine:
    def __init__(self, db_conn, gui, audio):
        self.db = db_conn
        self.gui = gui
        self.audio = audio

        # Monitoring modules
        self.procmon = ProcessMonitor(db_conn)
        self.netmon = NetworkMonitor(db_conn)
        self.clipmon = ClipboardGuard(db_conn)
        self.persistmon = PersistenceMonitor(db_conn)
        self.fsmon = FileSystemMonitor(db_conn)
        self.hardmon = HardeningMonitor(db_conn)
        self.intelmon = IntelMonitor(db_conn)

        # Correlation engine
        self.corr = CorrelationEngine(db_conn, gui, audio)

        self.running = False

    # ---------------- START / STOP ----------------
    def start(self):
        """Start monitoring in a background thread"""
        self.running = True
        t = threading.Thread(target=self.loop, daemon=True)
        t.start()

    def stop(self):
        """Stop monitoring"""
        self.running = False

    # ---------------- MAIN LOOP ----------------
    def loop(self):
        while self.running:
            try:
                events = []

                # Process monitor
                for t in self.procmon.scan_processes():
                    msg = f"[PROC-THREAT] {t['name']} (PID {t['pid']})"
                    self.gui.log_threat(msg, category="process")
                    self.audio.play("alert")
                    self.gui.update_status("Process threat detected!", color="red")
                    events.append({"type": "process", "msg": msg})

                # Network monitor
                for t in self.netmon.scan_ports():
                    msg = f"[NET-THREAT] Suspicious port {t['port']} (PID {t['pid']})"
                    self.gui.log_threat(msg, category="network")
                    self.audio.play("alert")
                    self.gui.update_status("Network threat detected!", color="orange")
                    events.append({"type": "network", "msg": msg})

                # Clipboard monitor
                for t in self.clipmon.check_clipboard():
                    msg = f"[CLIPBOARD-THREAT] {t}"
                    self.gui.log_threat(msg, category="clipboard")
                    self.audio.play("alert")
                    self.gui.update_status("Clipboard threat detected!", color="yellow")
                    events.append({"type": "clipboard", "msg": msg})

                # Persistence monitor
                for t in self.persistmon.scan_persistence():
                    msg = f"[PERSISTENCE-THREAT] {t}"
                    self.gui.log_threat(msg, category="persistence")
                    self.audio.play("alert")
                    self.gui.update_status("Persistence mechanism detected!", color="blue")
                    events.append({"type": "persistence", "msg": msg})

                # File system monitor
                for t in self.fsmon.scan_files():
                    msg = f"[FILESYSTEM-THREAT] {t}"
                    self.gui.log_threat(msg, category="filesystem")
                    self.audio.play("alert")
                    self.gui.update_status("File system threat detected!", color="white")
                    events.append({"type": "filesystem", "msg": msg})

                # Hardening monitor
                for t in self.hardmon.scan_hardening():
                    msg = f"[HARDENING-ISSUE] {t}"
                    self.gui.log_threat(msg, category="hardening")
                    self.audio.play("alert")
                    self.gui.update_status("Hardening issue detected!", color="lightgreen")
                    events.append({"type": "hardening", "msg": msg})

                # Intel monitor (extend later with IPs from network monitor)
                # For now, no IPs are being passed in directly.

                # Correlation across collected events
                if events:
                    self.corr.analyze(events)

            except Exception as e:
                self.gui.log("Dashboard", f"[Engine Error] {e}")

            time.sleep(3)