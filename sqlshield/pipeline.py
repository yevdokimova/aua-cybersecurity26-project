from __future__ import annotations

import os

from .allowlist import default_store as _allowlist
from .config import load_config, _env_or
from .engines.anomaly import AnomalyEngine
from .engines.llm_policy import LLMPolicyEngine, LLMPolicyConfig
from .engines.signature import SignatureEngine, DEFAULT_RULES
from .enricher import Enricher
from .parser import Parser
from .types import ParsedQuery, SessionInfo
from .verdict import Aggregator, FinalVerdict

_cfg = load_config()
_eng_cfg = _cfg.get("engines", {})
_sig_cfg = _eng_cfg.get("signature", {})
_anom_cfg = _eng_cfg.get("anomaly", {})
_llm_cfg = _eng_cfg.get("llm_policy", {})

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

_llm_policy = LLMPolicyEngine(LLMPolicyConfig(
    allowed_tables=_llm_cfg.get("allowed_tables", ["products", "messages", "chat_logs"]),
    block_mutations=bool(_llm_cfg.get("block_mutations", True)),
    max_row_limit=int(_llm_cfg.get("max_row_limit", 100)),
    require_where_on=_llm_cfg.get("require_where_on", ["users"]),
    max_join_depth=int(_llm_cfg.get("max_join_depth", 2)),
    block_subqueries=bool(_llm_cfg.get("block_subqueries", False)),
))

_aggregator = Aggregator(
    engines=[_signature, _anomaly, _llm_policy],
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
