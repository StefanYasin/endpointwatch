# 🛡️ SQSM — Stefan’s Quantum Security Monitor

SQSM turns your PC into a **cyber defense command center**.  
Where antivirus stops at protection, SQSM goes further: **visual monitoring, AI explanations, and one‑click threat neutralization**.

---

## ✨ What Makes SQSM Different

- **Matrix‑style Screensaver**  
  A living cyber dashboard — glowing green rain with real‑time overlays for system stats, security news, threats, and AI insights.

- **See Threats, Don’t Just Block Them**  
  SQSM shows you what’s happening: suspicious processes, hidden startup entries, network connections, clipboard hijacks, and file changes.

- **Smart Explanations**  
  Built‑in AI explains alerts in plain English, so you always know *why* something is dangerous.

- **One‑Click Neutralization**  
  If malware plants itself in startup, SQSM highlights it and lets you remove it instantly — no registry digging required.

- **Security News Feed**  
  Stay ahead with live updates from Hacker News, US‑CERT, Packet Storm, DEF CON, and Hak5.

- **Daily/Weekly Reports**  
  Generate polished Markdown reports that summarize your system’s security state and recent activity.

---

## 🚀 Getting Started

1. **Run as Administrator**  
   SQSM needs elevated permissions to monitor and neutralize startup threats.

2. **Install Dependencies**
	pip install -r requirements.txt

3. **Launch SQSM**  
	python main.py
	
4. **Set API Keys (Optional but Recommended)**  
- [VirusTotal](https://www.virustotal.com/) → file and process reputation lookups.  
- [AbuseIPDB](https://www.abuseipdb.com/) → IP reputation checks.  
- [OpenAI](https://platform.openai.com/) → AI explanations and insights.  

SQSM will automatically use them once saved.

---

## 🔍 Key Features

- **Threat Monitoring**  
- Process monitoring  
- Network connection tracking  
- Clipboard hijack detection  
- File system changes  
- Startup persistence watcher  

- **Threat Enrichment**  
- VirusTotal scans of suspicious files  
- AbuseIPDB checks for shady IPs  

- **Visual Dashboard**  
- Matrix‑rain screensaver with overlays  
- Color‑coded alerts (red = process, orange = network, cyan = persistence, etc.)  
- AI‑enhanced facts and security insights  

- **System Hardening Checks**  
- Defender, Firewall, UAC, Admin accounts  
- Alerts if critical protections are off  

---

## 🧹 Neutralizing Threats

1. Go to the **Threats tab**.  
2. Click **🧹 Neutralize Selected Threat**.  
3. A popup window will show current threats.  
4. Select the one you want to remove → confirm → SQSM cleans it up.  

---

## 💡 Why Use SQSM?

- Antivirus protects you in the background.  
- SQSM **empowers you** with visibility, explanations, and control.  
- It makes cybersecurity visual, interactive, and fun.  

---

## 📊 Example Use Cases

- Detect and remove unwanted startup programs.  
- Watch system health and network activity in real time.  
- Stay informed with live security news and hacking updates.  
- Learn cybersecurity with AI‑explained alerts.  

---

## ❤️ Credits

- Built on Python, Tkinter, and psutil.  
- Security intel from VirusTotal, AbuseIPDB, Hacker News, US‑CERT, Hak5, and DEF CON.  
- Inspired by classic hacker aesthetics — **the Matrix meets modern cybersecurity**.  

---