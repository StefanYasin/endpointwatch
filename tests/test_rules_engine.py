# tests/test_rules_engine.py
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.rules_engine import RulesEngine
from core.evidence_exporter import EvidenceExporter


def test_default_rules_load():
    """RulesEngine loads defaults when no rules.yaml exists."""
    with tempfile.TemporaryDirectory() as tmp:
        engine = RulesEngine(rules_path=os.path.join(tmp, "nope.yaml"))
        assert "process" in engine.rules
        assert "network" in engine.rules
        assert "persistence" in engine.rules


def test_process_match():
    engine = RulesEngine()
    hits = engine.match("process", "mimikatz.exe")
    assert len(hits) >= 1
    assert hits[0]["severity"] == "critical"
    assert hits[0]["name"] == "mimikatz"


def test_no_match():
    engine = RulesEngine()
    hits = engine.match("process", "chrome.exe")
    assert hits == []


def test_case_insensitive():
    engine = RulesEngine()
    hits = engine.match("process", "MIMIKATZ.EXE")
    assert len(hits) >= 1


def test_custom_yaml_loaded():
    """A user rules.yaml overrides defaults."""
    yaml_content = """
process:
  - name: my-rule
    pattern: customtool
    severity: high
    reason: user-defined
"""
    with tempfile.TemporaryDirectory() as tmp:
        rules_path = os.path.join(tmp, "rules.yaml")
        with open(rules_path, "w") as f:
            f.write(yaml_content)
        engine = RulesEngine(rules_path=rules_path)
        assert engine.match("process", "customtool.exe")[0]["name"] == "my-rule"


def test_evidence_export_writes_file():
    with tempfile.TemporaryDirectory() as tmp:
        exporter = EvidenceExporter(export_dir=tmp)
        path = exporter.export(
            {"type": "process", "name": "mimikatz.exe", "pid": 1234},
            [{"name": "mimikatz", "severity": "critical", "reason": "Credential-dumping tool"}],
        )
        assert os.path.exists(path)
        import json
        with open(path) as f:
            record = json.load(f)
        assert record["schema_version"] == "1.0"
        assert record["event"]["name"] == "mimikatz.exe"
        assert record["rule_matches"][0]["severity"] == "critical"


def test_evidence_report_export():
    with tempfile.TemporaryDirectory() as tmp:
        exporter = EvidenceExporter(export_dir=tmp)
        path = exporter.export_report([{"type": "process", "msg": "x"}, {"type": "net", "msg": "y"}])
        assert os.path.exists(path)
        import json
        with open(path) as f:
            report = json.load(f)
        assert report["event_count"] == 2
