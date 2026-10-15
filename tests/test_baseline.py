# tests/test_baseline.py
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.baseline import BaselineStore


def test_observe_counts(tmp_path):
    store = BaselineStore(str(tmp_path / "baseline.json"))
    assert store.observe("process", "chrome.exe", now=100) == 1
    assert store.observe("process", "chrome.exe", now=200) == 2
    assert store.observe("process", "powershell.exe", now=200) == 1
    assert store.total_entity_count("process") == 3


def test_known_entity_never_anomalous():
    store = BaselineStore(":memory:")  # path unused until save
    store.observe("process", "svchost.exe")
    assert store.is_anomalous("process", "svchost.exe", min_history=5) is False


def test_unknown_not_flagged_before_history_threshold():
    store = BaselineStore(":memory:")
    store.observe("process", "svchost.exe")
    # Only 1 observation total: below min_history, unknown stays quiet.
    assert store.is_anomalous("process", "mystery.exe", min_history=20) is False


def test_unknown_flagged_after_history_threshold():
    store = BaselineStore(":memory:")
    for i in range(20):
        store.observe("process", f"proc{i}.exe")
    assert store.is_anomalous("process", "mystery.exe", min_history=20) is True
    # Different type: baseline history is per-type, endpoint unknown stays quiet.
    assert store.is_anomalous("endpoint", "1.2.3.4:80", min_history=20) is False


def test_save_load_roundtrip(tmp_path):
    path = str(tmp_path / "baseline.json")
    store = BaselineStore(path)
    store.observe("process", "explorer.exe")
    store.save()

    loaded = BaselineStore(path)
    assert loaded.entity_seen("process", "explorer.exe")
    assert loaded.total_entity_count("process") == 1


def test_prune_removes_stale(tmp_path):
    path = str(tmp_path / "baseline.json")
    store = BaselineStore(path)
    store.observe("process", "old.exe", now=1_000_000)
    store.observe("process", "fresh.exe", now=time_now())
    removed = store.prune(max_age_days=90, now=time_now())
    assert removed == 1
    assert not store.entity_seen("process", "old.exe")
    assert store.entity_seen("process", "fresh.exe")


def test_known_entities_sorted():
    store = BaselineStore(":memory:")
    store.observe("process", "z.exe")
    store.observe("process", "a.exe")
    store.observe("endpoint", "x:1")
    assert store.known_entities("process") == ["a.exe", "z.exe"]


def time_now():
    import time
    return time.time()
