from __future__ import annotations

import os

from .allowlist import default_store as _allowlist
from .config import load_config, _env_or
from .engines.anomaly import AnomalyEngine
from .engines.signature import SignatureEngine, DEFAULT_RULES
from .enricher import Enricher
from .parser import Parser
from .types import ParsedQuery, SessionInfo
from .verdict import Aggregator, FinalVerdict

_cfg = load_config()
_eng_cfg = _cfg.get("engines", {})
_sig_cfg = _eng_cfg.get("signature", {})
_anom_cfg = _eng_cfg.get("anomaly", {})

_parser = Parser()
_enricher = Enricher()

_signature = SignatureEngine(
    rules=DEFAULT_RULES,
    strictness=str(_env_or("SHIELD_STRICTNESS", _sig_cfg.get("strictness"), "medium")),
    bypass_fingerprints=_allowlist,
)

_anomaly = AnomalyEngine(
    learning_queries=int(_env_or("ANOMALY_LEARNING_QUERIES", _anom_cfg.get("learning_queries"), 100)),
    block_threshold=float(_env_or("ANOMALY_BLOCK_THRESHOLD", _anom_cfg.get("block_threshold"), 0.7)),
)

_aggregator = Aggregator(
    engines=[_signature, _anomaly],
    mode=str(_env_or("SHIELD_MODE", _eng_cfg.get("mode"), "enforce")),
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
