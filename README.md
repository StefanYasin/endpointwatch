<div align="center">

[![Stars](https://img.shields.io/github/stars/StefanYasin/endpointwatch?style=flat)]
[![License](https://img.shields.io/github/license/StefanYasin/endpointwatch?style=flat)]
[![Issues](https://img.shields.io/github/issues/StefanYasin/endpointwatch?style=flat)]
[![Last commit](https://img.shields.io/github/last-commit/StefanYasin/endpointwatch?style=flat)]
[![Language](https://img.shields.io/github/languages/top/StefanYasin/endpointwatch?style=flat)]
[![Tests](https://img.shields.io/github/actions/workflow/status/StefanYasin/endpointwatch/ci.yml?style=flat&label=tests)]

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
- **Baseline mode** *(roadmap)* — learn what processes and connection targets are normal on this endpoint, then flag anything new that shows up
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

## 🧠 Baseline Mode

Learn what's normal, then flag drift. Baseline lives in `database/baseline.json` and works completely offline:

```bash
# Learn the current state (run a few times over days/weeks for a real profile)
python baseline_check.py --learn

# Check the current state against the baseline (exit 1 = anomalies found)
python baseline_check.py

# Machine-readable output for cron/CI
python baseline_check.py --out findings.json
```

Unknown processes and connection targets only flag once the baseline has enough history (`--min-history`, default 20), so the learning window doesn't spam you. Configuration reference: `config/baseline.yaml.example`.

## 🧪 Tests

```bash
python -m pytest tests/ -v
```

## 📋 Roadmap

- [x] YAML detection rules
- [x] JSON evidence export
- [x] Baseline/learning mode (flag deviations from a learned normal)
- [ ] SIEM ingestion guide (Splunk/ELK examples)

## ⚠️ Notes

- Windows-focused (uses psutil, Tkinter)
- LLM alerts are optional — works fully offline without AI keys
- Maintained actively — this is the *maintained alternative* in a field of abandoned live-response tools

## FAQ

**What does endpointwatch monitor?**

Processes, network connections, persistence/startup entries, clipboard hijacks, and file changes, plus a live security news feed. See the feature list for the full set.

**Do I need API keys?**

No. The dashboard, detection rules, and evidence export run fully offline. VirusTotal, AbuseIPDB, and the plain-English LLM alerts are optional integrations you enable with your own keys.

**How does baseline mode work?**

Run `python baseline_check.py --learn` a few times over days or weeks so it learns your normal processes and connection targets. Then `python baseline_check.py` flags anything it has never seen, once enough history exists (`--min-history`, default 20). Exit code 1 means anomalies were found.

**How do I write my own detection rules?**

Copy `config/rules.yaml.example` to `config/rules.yaml`. Rules support `process`, `network`, and `persistence` categories with case-insensitive substring matching and severity levels from info to critical.

**Where does my evidence go?**

Every rule match writes a timestamped JSON evidence pack to the `evidence/` folder, ready to feed a SIEM or ticketing system.

**Does it send data anywhere?**

No. Everything stays on the machine it runs on.

**How do I run the tests?**

`python -m pytest tests/ -v`

## License

MIT

---

Built and maintained by **Stefan Yasin** — technical operations, infrastructure, and applied AI. [Portfolio](https://stefanyasin.github.io/) · [LinkedIn](https://www.linkedin.com/in/stefanyasin/) · [Buy me a coffee](https://buymeacoffee.com/stefanthepro)