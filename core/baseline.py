"""Behavioral baseline engine: learn what's normal, flag what isn't.

Records observed entities (process names, remote endpoints, autostart
entries, ...) in a JSON store with observation counts and first/last-seen
timestamps. An entity is an anomaly candidate when the baseline has enough
history for its type but has never seen this entity before.

Pure stdlib, no GUI/hardware deps: unit-testable anywhere. This is the
"baseline mode" from the endpointwatch roadmap: establish what normal
looks like, then alert on drift instead of relying only on static rules.
"""

import json
import os
import threading
import time


class BaselineStore:
    """Persistent baseline of observed system entities."""

    def __init__(self, path="database/baseline.json"):
        self.path = path
        self._lock = threading.Lock()
        self.data = {"entities": {}, "meta": {"created": time.time()}}
        self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict) and "entities" in loaded:
                self.data = loaded
        except (OSError, ValueError):
            # First run: start empty.
            pass

    def save(self):
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, self.path)

    def observe(self, entity_type, entity_value, now=None):
        """Record one observation; returns the entity's total count."""
        now = now or time.time()
        key = f"{entity_type}:{entity_value}"
        with self._lock:
            entity = self.data["entities"].get(key)
            if entity is None:
                entity = {
                    "type": entity_type,
                    "value": entity_value,
                    "count": 0,
                    "first_seen": now,
                    "last_seen": now,
                }
                self.data["entities"][key] = entity
            entity["count"] += 1
            entity["last_seen"] = now
            return entity["count"]

    def entity_seen(self, entity_type, entity_value):
        return f"{entity_type}:{entity_value}" in self.data["entities"]

    def total_entity_count(self, entity_type):
        """Sum of observations for all entities of a type (history size)."""
        return sum(
            e["count"] for e in self.data["entities"].values()
            if e["type"] == entity_type
        )

    def known_entities(self, entity_type):
        """Sorted list of distinct entity values seen for a type."""
        return sorted(
            e["value"] for e in self.data["entities"].values()
            if e["type"] == entity_type
        )

    def is_anomalous(self, entity_type, entity_value, min_history=20):
        """True if this entity is unseen and the baseline has enough history.

        A known entity is never anomalous. An unknown entity is only
        flagged once the baseline has at least `min_history` total
        observations for that type, so the learning window does not
        produce a storm of false positives.
        """
        if self.entity_seen(entity_type, entity_value):
            return False
        return self.total_entity_count(entity_type) >= min_history

    def prune(self, max_age_days=90, now=None):
        """Drop entities not seen recently; returns count removed."""
        now = now or time.time()
        cutoff = now - max_age_days * 86400
        with self._lock:
            stale = [
                key for key, entity in self.data["entities"].items()
                if entity["last_seen"] < cutoff
            ]
            for key in stale:
                del self.data["entities"][key]
        return len(stale)
