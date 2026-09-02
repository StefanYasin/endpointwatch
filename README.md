<div align="center">

[![Stars](https://img.shields.io/github/stars/StefanYasin/endpointwatch?style=flat)]
[![License](https://img.shields.io/github/license/StefanYasin/endpointwatch?style=flat)]
[![Issues](https://img.shields.io/github/issues/StefanYasin/endpointwatch?style=flat)]
[![Last commit](https://img.shields.io/github/last-commit/StefanYasin/endpointwatch?style=flat)]
[![Language](https://img.shields.io/github/languages/top/StefanYasin/endpointwatch?style=flat)]

</div>

# 🛡️ endpointwatch

**Live-response endpoint monitoring for Windows.** Watches processes, connections, and persistence — enriched with VirusTotal + AbuseIPDB lookups and plain-English LLM alerts.

<div align="center">
<h3>Install</h3>
</div>

```bash
pip install endpointwatch
```

Then run:

```bash
endpointwatch
```

Where antivirus stops at protection, endpointwatch goes further: **visual monitoring, YAML-driven detection rules, structured evidence export, AI explanations, and one-click threat neutralization**.

---

## ✨ What Makes endpointwatch Different

- **Matrix-style live dashboard** — glowing green rain with real-time overlays for system stats, security news, threats, and AI insights
- **See threats, don't just block them** — suspicious processes, hidden startup entries, network connections, clipboard hijacks, file changes
- **YAML detection rules** *(roadmap #1)* — define your own detections in `config/rules.yaml` without touching code. Ships with defaults for mimikatz, encoded PowerShell, C2 ports, persistence keys
- **JSON evidence export** *(roadmap #1)* — every rule match writes a structured, SIEM-friendly evidence pack to `evidence/` for incident response
- **Smart explanations** — built-in AI explains alerts in plain English
- **One-click neutralization** — remove malware from startup instantly, no registry digging
- **Security news feed** — live updates from Hacker News, US-CERT, Packet Storm, DEF CON, Hak5
- **Daily/weekly reports**

## 🚀 Quick Start

```bash
pip install -r requirements.txt
python main.py
```

## 🧩 Detection Rules (YAML)

Copy `config/rules.yaml.example` to `config/rules.yaml`:

```yaml
process:
  - name: mimikatz
    pattern: mimikatz
    severity: critical
    reason: Credential-dumping tool
  - name: powershell-encoded
    pattern: "-enc"
    severity: high
    reason: Encoded PowerShell command
```

Categories: `process`, `network`, `persistence`. Rules are substring-matched (case-insensitive). Severity: `info | low | medium | high | critical`.

## 📦 Evidence Export

Every rule match writes a timestamped JSON file to `evidence/`:

```json
{
  "schema_version": "1.0",
  "event": {"type": "process", "name": "mimikatz.exe", "pid": 1234},
  "rule_matches": [{"name": "mimikatz", "severity": "critical", "reason": "Credential-dumping tool"}]
}
```

Feed these to your SIEM, ticketing system, or IR workflow.

## 🧪 Tests

```bash
python -m pytest tests/ -v
```

## 📋 Roadmap

- [x] YAML detection rules
- [x] JSON evidence export
- [ ] Baseline/learning mode (flag deviations from a learned normal)
- [ ] SIEM ingestion guide (Splunk/ELK examples)

## ⚠️ Notes

- Windows-focused (uses psutil, Tkinter)
- LLM alerts are optional — works fully offline without AI keys
- Maintained actively — this is the *maintained alternative* in a field of abandoned live-response tools

## License

MIT
