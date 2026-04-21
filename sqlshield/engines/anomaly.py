"""
Phase 2B — Statistical anomaly detection engine.

Per-(user, role) behavioural baselines built incrementally during a
learning period; after the learning period each query is scored across
five dimensions and the maximum is the engine's anomaly score.

Inspired by Kamra et al., "Detecting Anomalous Access Patterns in
Relational Databases" (VLDB Journal 2008). This is the simplest of the
three approaches discussed in the design notes (no extra dependencies,
interpretable, fast).

Persistence
-----------
Baselines are written to ``baselines.json`` next to the audit log so
they survive restarts. Path is overridable via the ``BASELINES_FILE``
environment variable.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

from ..types import Action, EngineVerdict, ParsedQuery, QueryType
from . import BaseEngine


# ---------------------------------------------------------------------------
# Per-user baseline
# ---------------------------------------------------------------------------

_MUTATIONS = {QueryType.INSERT.name, QueryType.UPDATE.name,
              QueryType.DELETE.name, QueryType.DDL.name}


@dataclass
class Baseline:
    user: str
    role: str
    seen_fingerprints: dict       = field(default_factory=dict)
    seen_tables: dict             = field(default_factory=dict)
    query_type_dist: dict         = field(default_factory=dict)
    active_hours: list            = field(default_factory=lambda: [0] * 24)
    literal_sum: float            = 0.0
    literal_sum_sq: float         = 0.0
    join_sum: float               = 0.0
    join_sum_sq: float            = 0.0
    total_queries: int            = 0
    first_seen: float             = 0.0
    last_seen: float              = 0.0
    learning: bool                = True

    # ---- statistics helpers ------------------------------------------------

    def literal_stats(self) -> tuple[float, float]:
        return _mean_std(self.literal_sum, self.literal_sum_sq, self.total_queries)

    def join_stats(self) -> tuple[float, float]:
        return _mean_std(self.join_sum, self.join_sum_sq, self.total_queries)

    # ---- learning ----------------------------------------------------------

    def absorb(self, query: ParsedQuery) -> None:
        now = time.time()
        if not self.first_seen:
            self.first_seen = now
        self.last_seen = now

        self.seen_fingerprints[query.ast_fingerprint] = (
            self.seen_fingerprints.get(query.ast_fingerprint, 0) + 1
        )
        for t in query.tables:
            self.seen_tables[t] = self.seen_tables.get(t, 0) + 1

        qt = query.query_type.name
        self.query_type_dist[qt] = self.query_type_dist.get(qt, 0) + 1

        hour = datetime.fromtimestamp(now).hour
        self.active_hours[hour] += 1

        self.literal_sum    += query.literal_count
        self.literal_sum_sq += query.literal_count ** 2
        self.join_sum       += query.join_depth
        self.join_sum_sq    += query.join_depth ** 2
        self.total_queries  += 1


def _mean_std(s: float, s2: float, n: int) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    mean = s / n
    var  = max(0.0, s2 / n - mean * mean)
    return mean, math.sqrt(var)


# ---------------------------------------------------------------------------
# Anomaly engine
# ---------------------------------------------------------------------------

_DEFAULT_LEARNING_QUERIES = 100
_BLOCK_THRESHOLD          = 0.7
_Z_THRESHOLD              = 3.0


class AnomalyEngine(BaseEngine):
    """
    Per-user statistical anomaly detector.

    Behaviour
    ---------
    * During the learning period (``learning_queries`` queries per user),
      every query is absorbed into the baseline and the engine returns
      ``ALLOW`` with score 0.
    * After learning, the engine scores each query along five dimensions
      and reports ``BLOCK`` if the aggregate score reaches
      ``block_threshold`` (default 0.7).
    """

    def __init__(self,
                 learning_queries: int = _DEFAULT_LEARNING_QUERIES,
                 block_threshold: float = _BLOCK_THRESHOLD,
                 store_path: Optional[str] = None) -> None:
        self.learning_queries = learning_queries
        self.block_threshold  = block_threshold
        self.store_path       = store_path or os.environ.get(
            "BASELINES_FILE",
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "logs", "baselines.json"),
        )
        self._baselines: dict[tuple[str, str], Baseline] = {}
        self._lock = threading.Lock()
        self._load()

    @property
    def name(self) -> str:
        return "anomaly"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(self, query: ParsedQuery) -> EngineVerdict:
        t0 = time.perf_counter()
        ctx = query.context
        user = ctx.session.user if ctx else "anonymous"
        role = ctx.role        if ctx else "anonymous"

        with self._lock:
            key = (user, role)
            baseline = self._baselines.get(key)
            if baseline is None:
                baseline = Baseline(user=user, role=role)
                self._baselines[key] = baseline

            if baseline.learning:
                baseline.absorb(query)
                if baseline.total_queries >= self.learning_queries:
                    baseline.learning = False
                self._persist()
                return _verdict(Action.ALLOW, 0.0,
                                ["learning"], ["ANOM-LEARN"], t0)

            score, reasons, rule_ids = self._score(query, baseline)
            # Always continue absorbing post-learning so the baseline
            # tracks slow drift; this mirrors how real IDS baselines work.
            baseline.absorb(query)
            self._persist()

        action = Action.BLOCK if score >= self.block_threshold else Action.ALLOW
        return _verdict(action, score, reasons, rule_ids, t0)

    def reset_baseline(self, user: str, role: Optional[str] = None) -> bool:
        """Drop a user's baseline so it re-enters the learning phase."""
        with self._lock:
            removed = False
            for key in list(self._baselines.keys()):
                if key[0] == user and (role is None or key[1] == role):
                    del self._baselines[key]
                    removed = True
            if removed:
                self._persist()
            return removed

    def export_baselines(self) -> dict:
        with self._lock:
            return {f"{u}|{r}": asdict(b) for (u, r), b in self._baselines.items()}

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score(self, query: ParsedQuery, baseline: Baseline):
        """
        Return ``(score, reasons, rule_ids)`` for a post-learning query.

        Five independent dimensions; the engine reports the maximum so a
        single very strong signal is enough to block.
        """
        scores: list[float] = []
        reasons: list[str]  = []
        rule_ids: list[str] = []

        # 1) Novel AST fingerprint — query shape never seen for this user.
        if query.ast_fingerprint and query.ast_fingerprint not in baseline.seen_fingerprints:
            scores.append(1.0)
            reasons.append("ANOM-001: novel AST fingerprint")
            rule_ids.append("ANOM-001")

        # 2) Novel table — never accessed by this user before.
        novel_tables = [t for t in query.tables if t not in baseline.seen_tables]
        if novel_tables:
            scores.append(0.8)
            reasons.append(f"ANOM-002: novel table(s): {', '.join(novel_tables)}")
            rule_ids.append("ANOM-002")

        # 3) First mutation — user was read-only and is now writing.
        seen_types = set(baseline.query_type_dist.keys())
        if (query.query_type.name in _MUTATIONS
                and not (seen_types & _MUTATIONS)):
            scores.append(0.9)
            reasons.append("ANOM-003: first mutation from a previously read-only user")
            rule_ids.append("ANOM-003")

        # 4) Complexity spike — z-score on literal_count or join_depth.
        z_lit  = _z(query.literal_count, *baseline.literal_stats())
        z_join = _z(query.join_depth,    *baseline.join_stats())
        z_max  = max(z_lit, z_join)
        if z_max > _Z_THRESHOLD:
            spike_score = min(1.0, z_max / 6.0)  # z=6 → score 1.0
            scores.append(spike_score)
            reasons.append(
                f"ANOM-004: complexity spike (z_lit={z_lit:.1f}, z_join={z_join:.1f})"
            )
            rule_ids.append("ANOM-004")

        # 5) Temporal anomaly — query at an hour the user has never used.
        hour = datetime.fromtimestamp(time.time()).hour
        if baseline.active_hours[hour] == 0:
            scores.append(0.6)
            reasons.append(f"ANOM-005: query at unusual hour ({hour:02d}:00)")
            rule_ids.append("ANOM-005")

        if not scores:
            return 0.0, [], []
        return max(scores), reasons, rule_ids

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not os.path.exists(self.store_path):
            return
        try:
            with open(self.store_path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        for key, raw in data.items():
            try:
                user, role = key.split("|", 1)
            except ValueError:
                continue
            baseline = Baseline(user=user, role=role)
            for k, v in raw.items():
                if hasattr(baseline, k):
                    setattr(baseline, k, v)
            self._baselines[(user, role)] = baseline

    def _persist(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
            tmp = self.store_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.export_baselines_unlocked(), f)
            os.replace(tmp, self.store_path)
        except OSError:
            # Persistence failures must not break the request path.
            pass

    def export_baselines_unlocked(self) -> dict:
        return {f"{u}|{r}": asdict(b) for (u, r), b in self._baselines.items()}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _z(x: float, mean: float, std: float) -> float:
    if std <= 1e-9:
        return 0.0
    return abs((x - mean) / std)


def _verdict(action: Action, score: float, reasons, rule_ids, t0) -> EngineVerdict:
    return EngineVerdict(
        engine="anomaly",
        action=action,
        score=score,
        reasons=list(reasons),
        rule_ids=list(rule_ids),
        latency_ms=(time.perf_counter() - t0) * 1000.0,
    )
