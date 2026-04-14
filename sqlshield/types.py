from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, auto


class QueryType(IntEnum):
    SELECT  = auto()
    INSERT  = auto()
    UPDATE  = auto()
    DELETE  = auto()
    DDL     = auto()
    DCL     = auto()
    ADMIN   = auto()
    UNKNOWN = auto()


class Action(IntEnum):
    ALLOW = 0
    BLOCK = 1


@dataclass
class ParsedQuery:
    raw_sql: str
    normalized_sql: str   = ""
    ast_fingerprint: str  = ""
    query_type: QueryType = QueryType.UNKNOWN
    tables: list[str]     = field(default_factory=list)
    has_union: bool       = False
    has_or: bool          = False
    has_comment: bool     = False
    has_stacked: bool     = False
    has_subquery: bool    = False
    join_depth: int       = 0
    literal_count: int    = 0


@dataclass
class EngineVerdict:
    engine: str
    action: Action      = Action.ALLOW
    score: float        = 0.0
    reasons: list[str]  = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    latency_ms: float   = 0.0


@dataclass
class AuditRecord:
    id: str
    timestamp: float
    user: str
    role: str
    source_ip: str
    source_tag: str
    database: str
    query_type: str
    raw_sql: str
    normalized_sql: str
    ast_fingerprint: str
    tables: list[str]
    final_action: str
    engine_results: list[dict]
    total_latency_ms: float
    proxy_mode: str
