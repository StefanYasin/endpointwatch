import tkinter as tk
import random, time, psutil, feedparser, sqlite3, threading, json, os
from notifications.audio_alerts import AudioAlerts

# Optional AI
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

from modules.intel_feeds import IntelFeeds

class MatrixScreensaver:
    def __init__(self, db_path="database/security.db"):
        self.root = tk.Toplevel()
        self.root.attributes("-fullscreen", True)
        self.root.configure(bg="black")
        self.root.bind("<Escape>", lambda e: self.root.destroy())
        self.root.bind("<Any-KeyPress>", lambda e: self.root.destroy())
        self.root.bind("<Motion>", lambda e: self.root.destroy())

        self.canvas = tk.Canvas(self.root, bg="black", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        # Matrix rain setup
        self.font_size = 18
        self.chars = "01ABCDEFGHIJKLMNOPQRSTUVWXYZ#$%&*"
        self.width = self.root.winfo_screenwidth()
        self.height = self.root.winfo_screenheight()
        self.columns = int(self.width / self.font_size)
        self.drops = [random.randint(0, self.height // self.font_size) for _ in range(self.columns)]

        # Overlays
        self.setup_overlays()

        # DB connection (fresh per screensaver)
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.audio = AudioAlerts()

        # AI
        self.ai_client = None
        if OpenAI:
            try:
                from config import load_api_keys
                keys = load_api_keys()
                if keys.get("openai"):
                    self.ai_client = OpenAI(api_key=keys["openai"])
            except Exception:
                pass

        # Intel feeds
        self.intel = IntelFeeds()

        # Threads
        threading.Thread(target=self.update_stats, daemon=True).start()
        threading.Thread(target=self.update_news, daemon=True).start()
        threading.Thread(target=self.update_threats, daemon=True).start()
        threading.Thread(target=self.update_facts, daemon=True).start()
        threading.Thread(target=self.update_graph, daemon=True).start()

        self.animate_matrix()

    def setup_overlays(self):
        # Stats box
        self.stats_box = tk.Frame(self.root, bg="#001100", bd=2)
        self.stats_text = tk.Label(self.stats_box, font=("Consolas", 14, "bold"),
                                   fg="#00ff00", bg="#001100", justify="left", anchor="nw")
        self.stats_text.pack(fill="both", expand=True)
        self.stats_box.place(x=20, y=20, width=500, height=120)

        # Wider News box
        self.news_box = tk.Frame(self.root, bg="#001122", bd=2)
        self.news_text = tk.Label(self.news_box, font=("Consolas", 13),
                                  fg="#00ffff", bg="#001122", justify="left", anchor="nw", wraplength=self.width-60)
        self.news_text.pack(fill="both", expand=True)
        self.news_box.place(x=20, y=150, width=self.width-40, height=180)

        # Threats box
        self.threat_box = tk.Frame(self.root, bg="#220000", bd=2)
        self.threat_text = tk.Label(self.threat_box, font=("Consolas", 14, "bold"),
                                    fg="#ff5555", bg="#220000", justify="left", anchor="nw")
        self.threat_text.pack(fill="both", expand=True)
        self.threat_box.place(x=20, y=340, width=self.width-40, height=220)

        # Facts box
        self.facts_box = tk.Frame(self.root, bg="#222200", bd=2)
        self.facts_text = tk.Label(self.facts_box, font=("Consolas", 13, "italic"),
                                   fg="#ffff88", bg="#222200", justify="left", anchor="nw", wraplength=self.width-60)
        self.facts_text.pack(fill="both", expand=True)
        self.facts_box.place(x=20, y=570, width=self.width-40, height=120)

        # Graph canvas (CPU/Memory)
        self.graph_canvas = tk.Canvas(self.root, bg="black", highlightthickness=0)
        self.graph_canvas.place(x=20, y=self.height-200, width=self.width-40, height=160)
        self.cpu_history, self.mem_history = [], []

    # ---------------- MATRIX RAIN ----------------
    def animate_matrix(self):
        self.canvas.delete("all")
        for i in range(self.columns):
            x = i * self.font_size
            y = self.drops[i] * self.font_size
            char = random.choice(self.chars)

            # head
            self.canvas.create_text(x, y, text=char, fill="#ccffcc",
                                    font=("Consolas", self.font_size, "bold"))

            # trailing fade
            for j in range(1, 6):
                trail_y = y - j * self.font_size
                if trail_y < 0: continue
                shade = max(0, 255 - j * 40)
                color = f"#{shade:02x}ff{shade:02x}"
                self.canvas.create_text(x, trail_y,
                                        text=random.choice(self.chars),
                                        fill=color,
                                        font=("Consolas", self.font_size))

            self.drops[i] += 1
            if self.drops[i] * self.font_size > self.height and random.random() > 0.975:
                self.drops[i] = 0
        self.root.after(50, self.animate_matrix)

    # ---------------- STATS ----------------
    def update_stats(self):
        while True:
            if not self.root.winfo_exists(): break
            try:
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory()
                net = psutil.net_io_counters()
                txt = (f"CPU: {cpu}%\n"
                       f"Memory: {mem.percent}% ({mem.used//(1024**2)}MB/{mem.total//(1024**2)}MB)\n"
                       f"Net IO: Sent {net.bytes_sent//1024} KB | Recv {net.bytes_recv//1024} KB")
                self.stats_text.config(text=txt)
            except Exception as e:
                self.stats_text.config(text=f"Stats Error: {e}")
            time.sleep(2)

    # ---------------- SECURITY NEWS ----------------
    def update_news(self):
        feeds = [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.us-cert.gov/ncas/alerts.xml",
            "https://rss.packetstormsecurity.com/news/",
            "https://www.defcon.org/atom.xml",
            "https://hak5.org/blogs/news.atom"
        ]
        while True:
            if not self.root.winfo_exists(): break
            headlines = []
            for url in feeds:
                try:
                    feed = feedparser.parse(url)
                    for entry in feed.entries[:2]:
                        headlines.append(f"- {entry.title}")
                except Exception:
                    continue
            if headlines:
                self.news_text.config(text="SECURITY NEWS:\n" + "\n".join(headlines[:10]))
            time.sleep(600)

    # ---------------- THREATS ----------------
    def update_threats(self):
        last_seen_id = -1
        while True:
            if not self.root.winfo_exists(): break
            try:
                cursor = self.db.cursor()
                cursor.execute("SELECT id, timestamp, type, name FROM threats ORDER BY id DESC LIMIT 5")
                rows = cursor.fetchall()
                lines = []
                for r in rows:
                    base = f"{r[1][-8:]} [{r[2]}] {r[3]}"
                    intel = None
                    if r[2] == "process" and self.intel.vt_key:
                        intel = self.intel.vt_lookup_file(r[3])
                    elif r[2] == "network" and self.intel.abuse_key:
                        ip = r[3].split()[-1]
                        intel = self.intel.abuse_lookup_ip(ip)
                    if intel:
                        base += f" ↳ {intel}"
                    lines.append(base)
                if lines:
                    self.threat_text.config(text="LATEST THREATS:\n" + "\n".join(lines))
                if rows and rows[0][0] != last_seen_id:
                    self.audio.play("alert")
                    last_seen_id = rows[0][0]
            except Exception as e:
                self.threat_text.config(text=f"DB Error: {e}")
            time.sleep(10)

    # ---------------- FACTS ----------------
    def update_facts(self):
        static_facts = [
            "Quantum computers use qubits instead of bits.",
            "Zero-trust architecture is the future of cybersecurity.",
            "Cybercrime costs expected to hit $10.5 trillion by 2025.",
            "Linux powers 90% of the world’s supercomputers.",
            "Red teams simulate attackers to strengthen defenses."
        ]
        i = 0
        while True:
            if not self.root.winfo_exists(): break
            try:
                if self.ai_client and random.random() < 0.3:
                    try:
                        response = self.ai_client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": "Give one short cybersecurity insight in 20 words or less."}]
                        )
                        fact = response.choices[0].message.content.strip()
                    except Exception:
                        fact = random.choice(static_facts)
                else:
                    fact = static_facts[i % len(static_facts)]
                    i += 1
                self.facts_text.config(text="FACTS & IDEAS:\n" + fact)
            except Exception:
                pass
            time.sleep(30)

    # ---------------- GRAPH ----------------
    def update_graph(self):
        while True:
            if not self.root.winfo_exists(): break
            try:
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory().percent
                self.cpu_history.append(cpu)
                self.mem_history.append(mem)
                if len(self.cpu_history) > 100:
                    self.cpu_history.pop(0)
                    self.mem_history.pop(0)

                self.graph_canvas.delete("all")
                w = int(self.graph_canvas.winfo_width())
                h = int(self.graph_canvas.winfo_height())

                def draw_line(data, color, offset=0):
                    if len(data) > 1:
                        step = w / len(data)
                        coords = []
                        for i, val in enumerate(data):
                            x = i * step
                            y = h - (val / 100 * h) - offset
                            coords.extend([x, y])
                        self.graph_canvas.create_line(coords, fill=color, width=2)

                draw_line(self.cpu_history, "red")
                draw_line(self.mem_history, "yellow", offset=5)

                self.graph_canvas.create_text(10, 10, text="CPU (red) / MEM (yellow)",
                                              anchor="nw", fill="white", font=("Consolas", 10))
            except Exception:
                pass
            time.sleep(2)

    def run(self):
        self.root.mainloop()