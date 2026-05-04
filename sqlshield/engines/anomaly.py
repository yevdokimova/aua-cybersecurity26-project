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

try:
    import numpy as np
    from sklearn.neural_network import MLPRegressor
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False


_MUTATIONS = {QueryType.INSERT.name, QueryType.UPDATE.name,
              QueryType.DELETE.name, QueryType.DDL.name}

_DEFAULT_LEARNING_QUERIES = 100
_BLOCK_THRESHOLD          = 0.7
_Z_THRESHOLD              = 3.0
_MIN_AE_SAMPLES           = 10


@dataclass
class Baseline:
    user: str
    role: str
    seen_fingerprints: dict = field(default_factory=dict)
    seen_tables: dict       = field(default_factory=dict)
    query_type_dist: dict   = field(default_factory=dict)
    active_hours: list      = field(default_factory=lambda: [0] * 24)
    literal_sum: float      = 0.0
    literal_sum_sq: float   = 0.0
    join_sum: float         = 0.0
    join_sum_sq: float      = 0.0
    total_queries: int      = 0
    first_seen: float       = 0.0
    last_seen: float        = 0.0
    learning: bool          = True
    # Autoencoder training data and metadata
    feature_vectors: list   = field(default_factory=list)
    ae_trained: bool        = False
    ae_threshold: float     = 0.0
    ae_max_error: float     = 0.0

    def literal_stats(self) -> tuple[float, float]:
        return _mean_std(self.literal_sum, self.literal_sum_sq, self.total_queries)

    def join_stats(self) -> tuple[float, float]:
        return _mean_std(self.join_sum, self.join_sum_sq, self.total_queries)

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


def _extract_features(query: ParsedQuery) -> list:
    """8-dim feature vector: the same representation used by the autoencoder."""
    return [
        float(query.join_depth),
        float(query.literal_count),
        float(1 if query.has_union else 0),
        float(1 if query.has_or else 0),
        float(1 if query.has_subquery else 0),
        float(1 if query.has_comment else 0),
        float(1 if query.has_stacked else 0),
        float(query.query_type.value),
    ]


class AnomalyEngine(BaseEngine):
    def __init__(self,
                 learning_queries: int = _DEFAULT_LEARNING_QUERIES,
                 block_threshold: float = _BLOCK_THRESHOLD,
                 z_threshold: float = _Z_THRESHOLD,
                 min_ae_samples: int = _MIN_AE_SAMPLES,
                 store_path: Optional[str] = None) -> None:
        self.learning_queries = learning_queries
        self.block_threshold  = block_threshold
        self.z_threshold      = z_threshold
        self.min_ae_samples   = min_ae_samples
        self.store_path       = store_path or os.environ.get(
            "BASELINES_FILE",
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "logs", "baselines.json"),
        )
        self._baselines: dict[tuple[str, str], Baseline] = {}
        self._models: dict[tuple[str, str], object] = {}
        self._lock = threading.Lock()
        self._load()

    @property
    def name(self) -> str:
        return "anomaly"

    def inspect(self, query: ParsedQuery) -> EngineVerdict:
        t0 = time.perf_counter()
        ctx  = query.context
        user = ctx.session.user if ctx else "anonymous"
        role = ctx.role         if ctx else "anonymous"

        with self._lock:
            key      = (user, role)
            baseline = self._baselines.get(key)
            if baseline is None:
                baseline = Baseline(user=user, role=role)
                self._baselines[key] = baseline

            if baseline.learning:
                baseline.feature_vectors.append(_extract_features(query))
                baseline.absorb(query)
                if baseline.total_queries >= self.learning_queries:
                    baseline.learning = False
                    self._train_autoencoder_for(key, baseline)
                self._persist()
                return _verdict(Action.ALLOW, 0.0, ["learning"], ["ANOM-LEARN"], t0)

            score, reasons, rule_ids = self._score(query, baseline, key)
            baseline.absorb(query)
            self._persist()

        action = Action.BLOCK if score >= self.block_threshold else Action.ALLOW
        return _verdict(action, score, reasons, rule_ids, t0)

    def reset_baseline(self, user: str, role: Optional[str] = None) -> bool:
        with self._lock:
            removed = False
            for key in list(self._baselines.keys()):
                if key[0] == user and (role is None or key[1] == role):
                    del self._baselines[key]
                    self._models.pop(key, None)
                    removed = True
            if removed:
                self._persist()
            return removed

    def export_baselines(self) -> dict:
        with self._lock:
            return {f"{u}|{r}": asdict(b) for (u, r), b in self._baselines.items()}

    def _train_autoencoder_for(self, key: tuple, baseline: Baseline) -> None:
        """
        Fits an 8→6→4→6→8 MLPRegressor autoencoder on the feature vectors
        collected during the learning period.  Falls back silently if
        scikit-learn is not installed or training fails.
        """
        if not _SKLEARN_AVAILABLE or len(baseline.feature_vectors) < self.min_ae_samples:
            return
        try:
            X = np.array(baseline.feature_vectors, dtype=float)
            model = MLPRegressor(
                hidden_layer_sizes=(6, 4, 6),
                activation="relu",
                solver="adam",
                max_iter=500,
                random_state=42,
            )
            model.fit(X, X)
            errors = np.mean((X - model.predict(X)) ** 2, axis=1)
            # Threshold: mean + 2σ of training reconstruction errors.
            # Floor at 1e-4 to avoid triggering on floating-point noise
            # when training data is perfectly uniform.
            baseline.ae_threshold = max(float(errors.mean() + 2 * errors.std()), 1e-4)
            baseline.ae_max_error = max(float(errors.max()), baseline.ae_threshold)
            baseline.ae_trained   = True
            self._models[key]     = model
        except Exception:
            pass  # fall back to statistical scoring

    def _ae_score(self, query: ParsedQuery, baseline: Baseline,
                  key: tuple) -> Optional[tuple]:
        """
        Returns (score, reason, rule_id) when reconstruction error exceeds
        the learned threshold, else None.

        Score mapping: ae_threshold → 0.75 (just triggers block), ae_max_error → 1.0.
        """
        if not baseline.ae_trained:
            return None
        model = self._models.get(key)
        if model is None:
            return None
        try:
            x     = np.array([_extract_features(query)], dtype=float)
            error = float(np.mean((x - model.predict(x)) ** 2))
        except Exception:
            return None

        if error <= baseline.ae_threshold:
            return None

        span  = baseline.ae_max_error - baseline.ae_threshold
        ratio = (error - baseline.ae_threshold) / (span + 1e-9)
        score = 0.75 + 0.25 * min(1.0, ratio)
        return (
            score,
            f"ANOM-AE: reconstruction error {error:.4f} > threshold {baseline.ae_threshold:.4f}",
            "ANOM-AE",
        )


    def _score(self, query: ParsedQuery, baseline: Baseline,
               key: tuple) -> tuple:
        scores:   list[float] = []
        reasons:  list[str]   = []
        rule_ids: list[str]   = []

        # Primary: autoencoder reconstruction error (replaces ANOM-004 when trained)
        ae_result = self._ae_score(query, baseline, key)
        if ae_result:
            s, r, rid = ae_result
            scores.append(s)
            reasons.append(r)
            rule_ids.append(rid)

        # ANOM-001: AST fingerprint never seen from this user
        if query.ast_fingerprint and query.ast_fingerprint not in baseline.seen_fingerprints:
            scores.append(1.0)
            reasons.append("ANOM-001: novel AST fingerprint")
            rule_ids.append("ANOM-001")

        # ANOM-002: table never accessed by this user
        novel_tables = [t for t in query.tables if t not in baseline.seen_tables]
        if novel_tables:
            scores.append(0.8)
            reasons.append(f"ANOM-002: novel table(s): {', '.join(novel_tables)}")
            rule_ids.append("ANOM-002")

        # ANOM-003: first write operation from a previously read-only user
        seen_types = set(baseline.query_type_dist.keys())
        if query.query_type.name in _MUTATIONS and not (seen_types & _MUTATIONS):
            scores.append(0.9)
            reasons.append("ANOM-003: first mutation from a previously read-only user")
            rule_ids.append("ANOM-003")

        # ANOM-004: z-score complexity spike — statistical fallback when AE not trained
        if not baseline.ae_trained:
            z_lit  = _z(query.literal_count, *baseline.literal_stats())
            z_join = _z(query.join_depth,    *baseline.join_stats())
            z_max  = max(z_lit, z_join)
            if z_max > self.z_threshold:
                scores.append(min(1.0, z_max / 6.0))
                reasons.append(f"ANOM-004: complexity spike (z_lit={z_lit:.1f}, z_join={z_join:.1f})")
                rule_ids.append("ANOM-004")

        # ANOM-005: temporal anomaly — not in the AE feature vector, always checked
        hour = datetime.fromtimestamp(time.time()).hour
        if baseline.active_hours[hour] == 0:
            scores.append(0.6)
            reasons.append(f"ANOM-005: query at unusual hour ({hour:02d}:00)")
            rule_ids.append("ANOM-005")

        if not scores:
            return 0.0, [], []
        return max(scores), reasons, rule_ids

    def _load(self) -> None:
        if not os.path.exists(self.store_path):
            return
        try:
            with open(self.store_path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        for key_str, raw in data.items():
            try:
                user, role = key_str.split("|", 1)
            except ValueError:
                continue
            baseline = Baseline(user=user, role=role)
            for k, v in raw.items():
                if hasattr(baseline, k):
                    setattr(baseline, k, v)
            key = (user, role)
            self._baselines[key] = baseline
            # Retrain AE from stored feature vectors (no pickle needed)
            if baseline.ae_trained and baseline.feature_vectors:
                self._train_autoencoder_for(key, baseline)

    def _persist(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
            tmp = self.store_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(
                    {f"{u}|{r}": asdict(b) for (u, r), b in self._baselines.items()},
                    f,
                )
            os.replace(tmp, self.store_path)
        except OSError:
            pass


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
