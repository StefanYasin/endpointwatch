import tkinter as tk
from tkinter import ttk, scrolledtext, PanedWindow, messagebox, Toplevel, Listbox, Scrollbar
import os, json, threading, time, psutil
from gui.screensaver import MatrixScreensaver
from modules.report_generator import ReportGenerator
from modules.hardening_monitor import HardeningMonitor
from modules.startup_neutralizer import StartupNeutralizer
from modules.intel_feeds import IntelFeeds


class MatrixUI:
    def __init__(self, root, audio, ai=None, db=None):
        self.root = root
        self.root.title("endpointwatch — live-response endpoint monitor")
        self.audio = audio
        self.ai = ai
        self.db = db

        self.neutralizer = StartupNeutralizer()
        self.intel = IntelFeeds()

        # Notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        # Dashboard + Threats
        self.logs = {}
        for tab in ["Dashboard", "Threats"]:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=tab)
            text = tk.Text(frame, bg="black", fg="lime", insertbackground="lime")
            text.pack(fill="both", expand=True)
            self.logs[tab] = text

            if tab == "Threats":
                btn = tk.Button(frame, text="🧹 Neutralize Threat",
                                command=self.neutralize_threat,
                                bg="black", fg="red", font=("Consolas", 11, "bold"))
                btn.pack(side="bottom", pady=5)

        # AI + Docs
        ai_docs_frame = PanedWindow(self.notebook, orient="horizontal")
        self.notebook.add(ai_docs_frame, text="AI + Docs")

        # Left: Chat
        ai_frame = ttk.Frame(ai_docs_frame)
        ai_docs_frame.add(ai_frame)
        self.chat_history = scrolledtext.ScrolledText(ai_frame, bg="black", fg="cyan",
                                                      insertbackground="white", wrap="word")
        self.chat_history.pack(fill="both", expand=True, padx=5, pady=5)
        entry_frame = tk.Frame(ai_frame, bg="black")
        entry_frame.pack(fill="x", padx=5, pady=5)
        self.chat_entry = tk.Entry(entry_frame, bg="black", fg="lime", insertbackground="lime")
        self.chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        tk.Button(entry_frame, text="Send", command=self.send_chat).pack(side="right")

        # Right: Docs
        docs_frame = ttk.Frame(ai_docs_frame)
        ai_docs_frame.add(docs_frame)
        self.docs_text = scrolledtext.ScrolledText(docs_frame, bg="black", fg="white",
                                                   wrap="word", insertbackground="white")
        self.docs_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.load_docs()

        # Security Posture
        posture_frame = ttk.Frame(self.notebook)
        self.notebook.add(posture_frame, text="Security Posture")
        self.posture_text = scrolledtext.ScrolledText(posture_frame, bg="black", fg="lightgreen", wrap="word")
        self.posture_text.pack(fill="both", expand=True)

        # Reports -> Resource Monitor
        reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(reports_frame, text="Resource Monitor")
        self.res_text = scrolledtext.ScrolledText(reports_frame, bg="black", fg="lightblue", wrap="word")
        self.res_text.pack(fill="both", expand=True)
        threading.Thread(target=self.update_resource_monitor, daemon=True).start()

        # Menubar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        ai_menu = tk.Menu(menubar, tearoff=0)
        ai_menu.add_command(label="Set API Keys", command=self.set_api_keys)
        ai_menu.add_command(label="Summarize Threats", command=self.summarize_threats)
        menubar.add_cascade(label="AI", menu=ai_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="▶ Screensaver Mode", command=self.launch_screensaver)
        menubar.add_cascade(label="View", menu=view_menu)

        test_menu = tk.Menu(menubar, tearoff=0)
        test_menu.add_command(label="Run Functionality Test", command=self.run_test)
        menubar.add_cascade(label="Test", menu=test_menu)

        # Intel status
        if self.intel.vt_key or self.intel.abuse_key:
            self.update_status("Intel Active: " +
                               ("VT " if self.intel.vt_key else "") +
                               ("AbuseIPDB" if self.intel.abuse_key else ""),
                               color="lightblue")
        else:
            self.update_status("Intel Disabled", color="red")

        # Hardening monitor
        if db:
            self.hardmon = HardeningMonitor(db)
            threading.Thread(target=self.refresh_posture_loop, daemon=True).start()

    # ---------------- DOCS ----------------
    def load_docs(self):
        docs = """# 🛡️ endpointwatch — live-response endpoint monitor

endpointwatch is your **visual cyber defense dashboard**.  
Where antivirus protects in silence, endpointwatch shows you what's happening, explains threats, and lets you neutralize them.

Tabs:
- Dashboard → logs & status
- Threats → live feed + neutralization
- AI + Docs → chat & documentation
- Security Posture → system hardening checks
- Resource Monitor → live CPU, Memory, Disk, Network
"""
        self.docs_text.insert("end", docs)

    # ---------------- LOGGING ----------------
    def log(self, tab, message):
        if tab in self.logs:
            self.logs[tab].insert("end", message + "\n")
            self.logs[tab].see("end")
        else:
            self.chat_history.insert("end", message + "\n")
            self.chat_history.see("end")

    def log_threat(self, message, category="process"):
        colors = {
            "process": "red", "network": "orange", "clipboard": "yellow",
            "persistence": "cyan", "filesystem": "white", "hardening": "lightgreen",
            "intel": "lightblue", "ai": "cyan", "correlated": "magenta"
        }
        color = colors.get(category, "white")
        self.logs["Threats"].tag_configure(category, foreground=color)
        self.logs["Threats"].insert("end", message + "\n", category)
        self.logs["Threats"].see("end")

        # Intel enrichment
        if category == "process" and self.intel.vt_key:
            filepath = message.split()[-1]
            intel = self.intel.vt_lookup_file(filepath)
            if intel:
                self.logs["Threats"].insert("end", f"   ↳ {intel}\n", "intel")
        elif category == "network" and self.intel.abuse_key:
            parts = message.split()
            ip = parts[2] if len(parts) > 2 else None
            if ip:
                intel = self.intel.abuse_lookup_ip(ip)
                if intel:
                    self.logs["Threats"].insert("end", f"   ↳ {intel}\n", "intel")

    # ---------------- STATUS ----------------
    def update_status(self, text, color="lime"):
        if not hasattr(self, "status_frame"):
            self.status_frame = tk.Frame(self.root, bg="black")
            self.status_frame.pack(fill="x", side="bottom")
            self.status_led = tk.Canvas(self.status_frame, width=20, height=20,
                                        bg="black", highlightthickness=0)
            self.status_led.pack(side="left", padx=5, pady=2)
            self.status_label = tk.Label(self.status_frame, text="", anchor="w",
                                         bg="black", fg="lime", font=("Courier", 10))
            self.status_label.pack(side="left", fill="x")
        self.status_label.config(text=text, fg=color)
        self.status_led.delete("all")
        self.status_led.create_oval(4, 4, 16, 16, fill=color)

    # ---------------- HARDENING REFRESH ----------------
    def refresh_posture_loop(self):
        while True:
            if not self.root.winfo_exists(): break
            try:
                results = self.hardmon.scan_hardening()
                self.posture_text.delete("1.0", "end")
                if results:
                    self.posture_text.insert("end", "⚠️ Issues Found:\n\n")
                    for r in results:
                        self.posture_text.insert("end", f"- {r}\n")
                else:
                    self.posture_text.insert("end", "✅ System hardening checks passed.\n")
            except Exception as e:
                self.posture_text.insert("end", f"Error: {e}\n")
            time.sleep(300)

    # ---------------- SCREENSAVER ----------------
    def launch_screensaver(self):
        self.log("Dashboard", "▶ Launching screensaver...")
        MatrixScreensaver().run()

    # ---------------- NEUTRALIZATION ----------------
    def neutralize_threat(self):
        threats_text = self.logs["Threats"].get("1.0", "end").strip().splitlines()
        if not threats_text:
            messagebox.showinfo("Neutralization", "No threats available to neutralize.")
            return
        win = Toplevel(self.root)
        win.title("Neutralize Threat")
        win.geometry("600x300")
        tk.Label(win, text="Select a threat to neutralize:",
                 font=("Consolas", 12, "bold")).pack(pady=5)
        frame = tk.Frame(win)
        frame.pack(fill="both", expand=True, padx=10, pady=5)
        scrollbar = Scrollbar(frame)
        scrollbar.pack(side="right", fill="y")
        listbox = Listbox(frame, selectmode="single", yscrollcommand=scrollbar.set,
                          bg="black", fg="red", font=("Consolas", 11))
        for t in threats_text:
            if "[" in t and "]" in t:
                listbox.insert("end", t)
        listbox.pack(fill="both", expand=True)
        scrollbar.config(command=listbox.yview)

        def do_neutralize():
            try:
                sel = listbox.get(listbox.curselection())
            except Exception:
                messagebox.showwarning("Neutralization", "No threat selected.")
                return
            confirm = messagebox.askyesno("Confirm Neutralization",
                                          f"Are you sure you want to neutralize this?\n\n{sel}")
            if not confirm:
                return
            msg = None
            if "Run" in sel:
                name = sel.split(":")[1].split("=")[0].strip()
                msg = self.neutralizer.remove_registry_run(name)
            elif "TaskName" in sel:
                task_name = sel.split(":")[-1].strip()
                msg = self.neutralizer.remove_scheduled_task(task_name)
            elif ".lnk" in sel or ".exe" in sel:
                path = sel.split(" ", 1)[-1].strip()
                msg = self.neutralizer.remove_startup_file(path)
            if msg:
                self.log("Dashboard", f"🧹 {msg}")
                messagebox.showinfo("Neutralization", msg)
            win.destroy()

        tk.Button(win, text="Neutralize", command=do_neutralize,
                  bg="black", fg="white", font=("Consolas", 11, "bold")).pack(pady=5)
        tk.Button(win, text="Cancel", command=win.destroy).pack(pady=2)

    # ---------------- RESOURCE MONITOR ----------------
    def update_resource_monitor(self):
        while True:
            if not self.root.winfo_exists(): break
            try:
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage("/")
                net = psutil.net_io_counters()

                txt = (f"CPU Usage: {cpu}%\n"
                       f"Memory: {mem.percent}% ({mem.used//(1024**2)}MB / {mem.total//(1024**2)}MB)\n"
                       f"Disk: {disk.percent}% used ({disk.used//(1024**3)}GB / {disk.total//(1024**3)}GB)\n"
                       f"Network: Sent {net.bytes_sent//1024} KB | Recv {net.bytes_recv//1024} KB\n")

                self.res_text.delete("1.0", "end")
                self.res_text.insert("end", txt)
            except Exception as e:
                self.res_text.insert("end", f"Error: {e}\n")
            time.sleep(3)

    # ---------------- TEST ----------------
    def run_test(self):
        self.log("Dashboard", "⚡ Running functionality test...")
        self.log_threat("[PROC-THREAT] test_process.exe (PID 999)", category="process")
        self.log_threat("[NET-THREAT] Suspicious port 4444 (PID 888)", category="network")
        self.log_threat("[CLIPBOARD-THREAT] Clipboard hijack detected", category="clipboard")
        self.update_status("Test threats injected", color="cyan")

    # ---------------- AI ----------------
    def send_chat(self):
        user_input = self.chat_entry.get().strip()
        if not user_input: return
        self.chat_history.insert("end", f"You: {user_input}\n")
        self.chat_history.see("end")
        self.chat_entry.delete("0", "end")
        if not self.ai:
            self.chat_history.insert("end", "⚠️ AI integration not available\n")
            return
        providers = self.ai.available_providers()
        if not providers:
            self.chat_history.insert("end", "⚠️ No API keys saved\n")
            return
        provider = providers[0]
        response = self.ai.chat(provider, user_input)
        self.chat_history.insert("end", f"AI ({provider}): {response}\n")
        self.chat_history.see("end")

    def set_api_keys(self):
        messagebox.showinfo("Keys", "API key settings go here.")

    def summarize_threats(self):
        self.log("AI", "Threat summary (AI).")