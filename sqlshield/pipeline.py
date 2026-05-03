from __future__ import annotations

import os

from .allowlist import default_store as _allowlist
from .engines.anomaly import AnomalyEngine
from .engines.signature import SignatureEngine, DEFAULT_RULES
from .enricher import Enricher
from .parser import Parser
from .types import ParsedQuery, SessionInfo
from .verdict import Aggregator, FinalVerdict

_parser = Parser()
_enricher = Enricher()
_signature = SignatureEngine(
    rules=DEFAULT_RULES,
    strictness=os.environ.get("SHIELD_STRICTNESS", "medium"),
    bypass_fingerprints=_allowlist,
)
_anomaly = AnomalyEngine(
    learning_queries=int(os.environ.get("ANOMALY_LEARNING_QUERIES", 100)),
)
_aggregator = Aggregator(
    engines=[_signature, _anomaly],
    mode=os.environ.get("SHIELD_MODE", "enforce"),
)


def inspect(sql: str, session: SessionInfo) -> tuple[FinalVerdict, ParsedQuery]:
    pq = _parser.parse(sql)
    _enricher.enrich(pq, session)
    return _aggregator.evaluate(pq), pq


def get_aggregator() -> Aggregator:
    return _aggregator


def get_anomaly_engine() -> AnomalyEngine:
    return _anomaly


def get_allowlist():
    return _allowlist
