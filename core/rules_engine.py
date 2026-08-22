# core/rules_engine.py
"""
YAML-driven detection rules for endpointwatch.
Community roadmap #1: YAML rules config so users define their own detections
without touching code. Loaded from config/rules.yaml (see rules.yaml.example).
"""

import os
import yaml
from datetime import datetime, timezone

# Default rules shipped with the project — used when no rules.yaml exists.
DEFAULT_RULES = {
    "process": [
        {"name": "mimikatz", "pattern": "mimikatz", "severity": "critical",
         "reason": "Credential-dumping tool"},
        {"name": "powershell-encoded", "pattern": "-enc", "severity": "high",
         "reason": "Encoded PowerShell command"},
        {"name": "rundll32-suspicious", "pattern": "rundll32", "severity": "medium",
         "reason": "Common LOLBins execution"},
    ],
    "network": [
        {"name": "unknown-external-port", "pattern": "4444", "severity": "high",
         "reason": "Common C2 reverse-shell port"},
        {"name": "tor-exit", "pattern": "9050", "severity": "medium",
         "reason": "Tor SOCKS port"},
    ],
    "persistence": [
        {"name": "run-key", "pattern": r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "severity": "high", "reason": "Registry Run key (startup persistence)"},
    ],
}


class RulesEngine:
    """Loads and matches YAML detection rules against events."""

    def __init__(self, rules_path=None):
        self.rules_path = rules_path or os.path.join(
            os.path.dirname(__file__), "..", "config", "rules.yaml")
        self.rules = self._load()

    def _load(self):
        """Load rules from YAML; fall back to defaults if missing/invalid."""
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}
                if isinstance(loaded, dict) and any(k in loaded for k in
                                                    ("process", "network", "persistence")):
                    return loaded
            except yaml.YAMLError as e:
                print(f"[rules] YAML parse error in {self.rules_path}: {e}")
        return DEFAULT_RULES

    def match(self, category, value):
        """
        Match a value (process name, port, registry path...) against rules.
        Returns list of matches: [{"name","severity","reason"}, ...]
        """
        hits = []
        value_l = str(value).lower()
        for rule in self.rules.get(category, []):
            pattern = str(rule.get("pattern", "")).lower()
            if pattern and pattern in value_l:
                hits.append({
                    "name": rule.get("name", pattern),
                    "severity": rule.get("severity", "medium"),
                    "reason": rule.get("reason", ""),
                    "matched_at": datetime.now(timezone.utc).isoformat(),
                })
        return hits

    def severity_rank(self, severity):
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 1)
