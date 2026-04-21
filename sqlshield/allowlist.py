"""
Phase 2F — Persistent fingerprint allowlist.

An operator-managed list of AST fingerprints that should bypass the
signature engine entirely. Persists to ``allowlist.json`` next to the
audit log; reads/writes are guarded by a single lock so the dashboard
server and the engine can share the same store safely.

The signature engine already supports a fingerprint allowlist via its
``bypass_fingerprints`` parameter; this module wraps that mechanism in a
live, persisted, API-managed store with metadata for each entry.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class AllowlistEntry:
    fingerprint: str
    raw_sql_example: str = ""
    normalized_sql: str  = ""
    added_at: float      = 0.0
    added_by: str        = "admin"
    reason: str          = ""


class AllowlistStore:
    """Thread-safe, JSON-backed allowlist."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.environ.get(
            "ALLOWLIST",
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "logs", "allowlist.json"),
        )
        self._lock = threading.Lock()
        self._entries: dict[str, AllowlistEntry] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def contains(self, fingerprint: str) -> bool:
        with self._lock:
            return fingerprint in self._entries

    def add(self, entry: AllowlistEntry) -> bool:
        if not entry.fingerprint:
            return False
        if not entry.added_at:
            entry.added_at = time.time()
        with self._lock:
            if entry.fingerprint in self._entries:
                return False
            self._entries[entry.fingerprint] = entry
            self._persist()
        return True

    def remove(self, fingerprint: str) -> bool:
        with self._lock:
            if fingerprint not in self._entries:
                return False
            del self._entries[fingerprint]
            self._persist()
        return True

    def get(self, fingerprint: str) -> Optional[AllowlistEntry]:
        with self._lock:
            return self._entries.get(fingerprint)

    def list_all(self) -> list[AllowlistEntry]:
        with self._lock:
            return sorted(self._entries.values(), key=lambda e: e.added_at)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        for fp, data in raw.items():
            try:
                self._entries[fp] = AllowlistEntry(**data)
            except TypeError:
                continue

    def _persist(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({fp: asdict(e) for fp, e in self._entries.items()}, f)
            os.replace(tmp, self.path)
        except OSError:
            pass


# Process-wide default store, shared by the engine and the dashboard.
default_store = AllowlistStore()
