from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class FeedbackEntry:
    audit_id: str
    label: str
    verdict: str
    fingerprint: str
    raw_sql: str
    normalized_sql: str
    reviewer: str       = "admin"
    note: str           = ""
    reviewed_at: float  = 0.0


class FeedbackStore:
    """Thread-safe, JSON-backed operator-feedback store."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.environ.get(
            "FEEDBACK_FILE",
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "logs", "feedback.json"),
        )
        self._lock = threading.Lock()
        self._entries: dict[str, FeedbackEntry] = {}
        self._mtime: float = 0.0
        self._load()

    def add(self, entry: FeedbackEntry) -> bool:
        if not entry.audit_id or entry.label not in ("true_positive", "false_positive"):
            return False
        if not entry.reviewed_at:
            entry.reviewed_at = time.time()
        with self._lock:
            self._entries[entry.audit_id] = entry
            self._persist()
        return True

    def remove(self, audit_id: str) -> bool:
        self._maybe_reload()
        with self._lock:
            if audit_id not in self._entries:
                return False
            del self._entries[audit_id]
            self._persist()
        return True

    def get(self, audit_id: str) -> Optional[FeedbackEntry]:
        self._maybe_reload()
        with self._lock:
            return self._entries.get(audit_id)

    def list_all(self) -> list[FeedbackEntry]:
        self._maybe_reload()
        with self._lock:
            return sorted(self._entries.values(), key=lambda e: e.reviewed_at)

    def labels_by_id(self) -> dict[str, str]:
        self._maybe_reload()
        with self._lock:
            return {k: v.label for k, v in self._entries.items()}

    def _maybe_reload(self) -> None:
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return
        if mtime <= self._mtime:
            return
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        with self._lock:
            self._entries = {}
            for aid, data in raw.items():
                try:
                    self._entries[aid] = FeedbackEntry(**data)
                except TypeError:
                    continue
        try:
            self._mtime = os.path.getmtime(self.path)
        except OSError:
            self._mtime = time.time()

    def _persist(self) -> None:
        try:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({k: asdict(v) for k, v in self._entries.items()}, f)
            os.replace(tmp, self.path)
            try:
                self._mtime = os.path.getmtime(self.path)
            except OSError:
                self._mtime = time.time()
        except OSError:
            pass


default_store = FeedbackStore()
