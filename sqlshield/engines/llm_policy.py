from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from ..types import Action, EngineVerdict, ParsedQuery, QueryType
from . import BaseEngine


_LIMIT_RE = re.compile(r"\blimit\s+(\d+)\b", re.IGNORECASE)


@dataclass
class LLMPolicyConfig:
    allowed_tables:    list[str] = field(default_factory=lambda: ["products", "messages", "chat_logs"])
    block_mutations:   bool      = True
    max_row_limit:     int       = 100
    require_where_on:  list[str] = field(default_factory=lambda: ["users"])
    max_join_depth:    int       = 2
    block_subqueries:  bool      = False


class LLMPolicyEngine(BaseEngine):
    def __init__(self, config: LLMPolicyConfig | None = None) -> None:
        self.config = config or LLMPolicyConfig()

    @property
    def name(self) -> str:
        return "llm_policy"

    def inspect(self, query: ParsedQuery) -> EngineVerdict:
        t0 = time.perf_counter()

        ctx = getattr(query, "context", None)
        source_tag = getattr(ctx, "source_tag", "") if ctx else ""
        if source_tag != "ai-agent":
            return EngineVerdict(
                engine=self.name, action=Action.ALLOW, score=0.0,
                reasons=[], rule_ids=[],
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        rule_ids: list[str] = []
        reasons:  list[str] = []

        cfg           = self.config
        allowed       = ({t.lower() for t in cfg.allowed_tables}
                         | {t.lower() for t in cfg.require_where_on})
        require_where = {t.lower() for t in cfg.require_where_on}
        raw_upper     = query.raw_sql.upper()

        # LLM-001 — schema scope
        offending = [t for t in query.tables if t.split(".")[-1] not in allowed]
        if offending:
            rule_ids.append("LLM-001")
            reasons.append(f"LLM-001: table(s) outside allowlist: {', '.join(offending)}")

        # LLM-002 — mutations forbidden
        if cfg.block_mutations and query.query_type in (
            QueryType.INSERT, QueryType.UPDATE, QueryType.DELETE,
            QueryType.DDL,    QueryType.DCL,    QueryType.ADMIN,
        ):
            rule_ids.append("LLM-002")
            reasons.append(f"LLM-002: AI agent attempted {query.query_type.name}")

        # LLM-003 — row limit
        if query.query_type == QueryType.SELECT:
            m = _LIMIT_RE.search(query.raw_sql)
            if not m:
                rule_ids.append("LLM-003")
                reasons.append("LLM-003: SELECT without LIMIT clause")
            else:
                try:
                    if int(m.group(1)) > cfg.max_row_limit:
                        rule_ids.append("LLM-003")
                        reasons.append(
                            f"LLM-003: LIMIT {m.group(1)} exceeds maximum {cfg.max_row_limit}"
                        )
                except ValueError:
                    pass

        # LLM-004 — WHERE required on sensitive tables
        if require_where & {t.split(".")[-1] for t in query.tables}:
            if " WHERE " not in raw_upper:
                rule_ids.append("LLM-004")
                reasons.append("LLM-004: sensitive table accessed without WHERE clause")

        # LLM-005 — join depth limit
        if query.join_depth > cfg.max_join_depth:
            rule_ids.append("LLM-005")
            reasons.append(
                f"LLM-005: join_depth={query.join_depth} exceeds max {cfg.max_join_depth}"
            )

        # LLM-006 — subqueries forbidden (off by default)
        if cfg.block_subqueries and query.has_subquery:
            rule_ids.append("LLM-006")
            reasons.append("LLM-006: subqueries are disallowed for AI agents")

        # LLM-007 — UNION is a strong prompt-injection signal
        if query.has_union:
            rule_ids.append("LLM-007")
            reasons.append("LLM-007: UNION in AI-generated query")

        action = Action.BLOCK if rule_ids else Action.ALLOW
        score  = min(1.0, 0.5 + 0.15 * len(rule_ids)) if rule_ids else 0.0

        return EngineVerdict(
            engine=self.name,
            action=action,
            score=score,
            reasons=reasons,
            rule_ids=rule_ids,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
        )
