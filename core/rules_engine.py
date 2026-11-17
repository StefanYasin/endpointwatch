# core/rules_engine.py
"""
YAML-driven detection rules for endpointwatch.
Community roadmap #1: YAML rules config so users define their own detections
without touching code. Loaded from config/rules.yaml (see rules.yaml.example).
"""

import os
import yaml
from datetime import datetime, timezone

# Wazuh-style severity ladder: every rule maps to a numeric level (0-16) with
# a human title, so alerts can be filtered by a single minimum threshold.
SEVERITY_LEVELS = {
    "info":     {"level": 2,  "title": "Informational"},
    "low":      {"level": 4,  "title": "Low"},
    "medium":   {"level": 6,  "title": "Medium"},
    "high":     {"level": 9,  "title": "High"},
    "critical": {"level": 12, "title": "Critical"},
}


def severity_level(severity):
    """Numeric level (0-16) for a severity name; unknown -> 4 (low)."""
    return SEVERITY_LEVELS.get(severity, SEVERITY_LEVELS["low"])["level"]

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

    def __init__(self, rules_path=None, min_level=0):
        self.rules_path = rules_path or os.path.join(
            os.path.dirname(__file__), "..", "config", "rules.yaml")
        self.rules = self._load()
        # A user-facing minimum alert threshold: rules below this level are
        # ignored entirely (the Wazuh log_alert_level idea, per-rule here).
        self.min_level = min_level or self.rules.get("min_alert_level", 0)

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
            severity = rule.get("severity", "medium")
            if severity_level(severity) < self.min_level:
                continue
            pattern = str(rule.get("pattern", "")).lower()
            if pattern and pattern in value_l:
                hits.append({
                    "name": rule.get("name", pattern),
                    "severity": severity,
                    "level": severity_level(severity),
                    "reason": rule.get("reason", ""),
                    "matched_at": datetime.now(timezone.utc).isoformat(),
                })
        return hits

    def severity_rank(self, severity):
        return severity_level(severity)

    def explain(self, category, value):
        """Matches plus why: for the rule tester and alert explanations."""
        hits = self.match(category, value)
        return [
            {**h, "why": f"pattern '{self._pattern_for(category, h['name'])}' "
                          f"found in '{value}'"}
            for h in hits
        ]

    def _pattern_for(self, category, name):
        for rule in self.rules.get(category, []):
            if rule.get("name") == name:
                return rule.get("pattern", "")
        return ""
