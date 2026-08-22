# core/evidence_exporter.py
"""
JSON evidence export for endpointwatch.
Community roadmap #1: structured, SIEM-friendly evidence packs so alerts can
be handed to incident response, ticketing, or external tooling.
"""

import json
import os
from datetime import datetime, timezone


class EvidenceExporter:
    """Writes structured evidence packs (JSON) for detected events."""

    def __init__(self, export_dir=None):
        self.export_dir = export_dir or os.path.join(
            os.path.dirname(__file__), "..", "evidence")
        os.makedirs(self.export_dir, exist_ok=True)

    def export(self, event, matches):
        """
        Persist one event + its rule matches as JSON.
        event: {"type","msg",...}; matches: list from RulesEngine.match()
        Returns path to written file.
        """
        record = {
            "schema_version": "1.0",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "rule_matches": matches,
        }
        # Filename: type-YYYYmmdd-HHMMSS.json
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_type = str(event.get("type", "event")).replace("/", "_")
        path = os.path.join(self.export_dir, f"{safe_type}-{stamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
        return path

    def export_report(self, events, path=None):
        """Export a batch report (e.g. daily/weekly) of all events."""
        if path is None:
            stamp = datetime.now().strftime("%Y%m%d")
            path = os.path.join(self.export_dir, f"report-{stamp}.json")
        report = {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(events),
            "events": events,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return path
