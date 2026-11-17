# tests/test_severity_and_tester.py
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.rules_engine import RulesEngine, severity_level


def test_severity_ladder():
    assert severity_level("info") == 2
    assert severity_level("critical") == 12
    assert severity_level("high") > severity_level("medium") > severity_level("low")


def test_match_includes_level():
    engine = RulesEngine(min_level=0)
    hits = engine.match("process", "mimikatz.exe")
    assert hits, "mimikatz should match default rules"
    assert hits[0]["level"] == 12
    assert hits[0]["severity"] == "critical"


def test_min_level_filters():
    engine = RulesEngine(min_level=10)
    hits = engine.match("process", "rundll32.exe")     # medium (6) - filtered out
    assert hits == []
    hits = engine.match("process", "mimikatz.exe")     # critical (12) - kept
    assert hits and hits[0]["name"] == "mimikatz"


def test_explain_names_the_pattern():
    engine = RulesEngine(min_level=0)
    out = engine.explain("process", "mimikatz.exe")
    assert out and "mimikatz" in out[0]["why"]
