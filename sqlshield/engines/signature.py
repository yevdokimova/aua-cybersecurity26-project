from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..types import Action, EngineVerdict, ParsedQuery
from . import BaseEngine


SEVERITY_SCORES: dict[str, float] = {
    "critical": 1.0,
    "high":     0.85,
    "medium":   0.6,
    "low":      0.3,
}

_BLOCK_SEVERITIES: dict[str, frozenset[str]] = {
    "high":   frozenset({"critical", "high", "medium", "low"}),
    "medium": frozenset({"critical", "high", "medium"}),
    "low":    frozenset({"critical", "high"}),
}


@dataclass
class Condition:
    has_union: bool | None            = None
    has_stacked: bool | None          = None
    has_comment: bool | None          = None
    has_subquery: bool | None         = None
    has_or: bool | None               = None
    query_types: list[str] | None     = None
    sql_contains: list[str] | None    = None
    min_literals: int | None          = None
    min_join_depth: int | None        = None
    table_blocklist: list[str] | None = None


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    conditions: list[Condition] = field(default_factory=list)


DEFAULT_RULES: list[Rule] = [
    Rule(
        id="SIG-001",
        name="UNION-based injection",
        description="UNION SELECT appended to a query to extract data from other tables.",
        severity="critical",
        conditions=[Condition(has_union=True, query_types=["SELECT"])],
    ),
    Rule(
        id="SIG-002",
        name="Stacked queries",
        description="Multiple SQL statements in a single query string.",
        severity="critical",
        conditions=[Condition(has_stacked=True)],
    ),
    Rule(
        id="SIG-003",
        name="Tautology attack",
        description="Always-true conditions injected into WHERE clauses.",
        severity="high",
        conditions=[
            Condition(has_or=True, sql_contains=["1=1"]),
            Condition(has_or=True, sql_contains=["'='"]),
            Condition(has_or=True, sql_contains=["1='1"]),
            Condition(has_or=True, sql_contains=["''='"]),
            Condition(has_or=True, sql_contains=["' or 'a'='a"]),
        ],
    ),
    Rule(
        id="SIG-004",
        name="Comment-based obfuscation",
        description="Empty inline comments (/**/) used to fragment SQL keywords.",
        severity="medium",
        conditions=[Condition(has_comment=True, sql_contains=["/**/"])],
    ),
    Rule(
        id="SIG-005",
        name="System table access",
        description="Queries targeting database system catalog and metadata tables.",
        severity="high",
        conditions=[
            Condition(table_blocklist=[
                "information_schema", "pg_catalog", "pg_shadow", "pg_authid",
                "pg_user", "pg_roles", "mysql.user", "sys.objects",
                "sysobjects", "sqlite_master",
            ]),
        ],
    ),
    Rule(
        id="SIG-006",
        name="Excessive literal injection",
        description="High literal count with OR — hallmark of automated injection tools.",
        severity="medium",
        conditions=[Condition(min_literals=5, has_or=True)],
    ),
    Rule(
        id="SIG-007",
        name="Sleep/benchmark injection",
        description="Time-based blind injection using database delay functions.",
        severity="critical",
        conditions=[
            Condition(sql_contains=["sleep("]),
            Condition(sql_contains=["benchmark("]),
            Condition(sql_contains=["pg_sleep("]),
            Condition(sql_contains=["waitfor delay"]),
        ],
    ),
    Rule(
        id="SIG-008",
        name="File operation injection",
        description="SQL that reads or writes files on the database server filesystem.",
        severity="critical",
        conditions=[
            Condition(sql_contains=["load_file("]),
            Condition(sql_contains=["into outfile"]),
            Condition(sql_contains=["into dumpfile"]),
            Condition(sql_contains=["copy from"]),
        ],
    ),
    Rule(
        id="SIG-009",
        name="Boolean-based blind injection",
        description="Conditional logic (CASE WHEN) inside a subquery combined with OR.",
        severity="high",
        conditions=[Condition(has_subquery=True, has_or=True, sql_contains=["case when"])],
    ),
    Rule(
        id="SIG-010",
        name="Error-based extraction",
        description="Functions that force sensitive values into database error messages.",
        severity="high",
        conditions=[
            Condition(sql_contains=["extractvalue("]),
            Condition(sql_contains=["updatexml("]),
            Condition(sql_contains=["convert(int,"]),
        ],
    ),
]


class SignatureEngine(BaseEngine):
    def __init__(
        self,
        rules: list[Rule] | None = None,
        bypass_fingerprints: set[str] | None = None,
        strictness: str = "medium",
    ) -> None:
        self.rules = rules if rules is not None else DEFAULT_RULES
        self.bypass = bypass_fingerprints if bypass_fingerprints is not None else set()
        self.strictness = strictness
        self._block_severities = _BLOCK_SEVERITIES.get(strictness, _BLOCK_SEVERITIES["medium"])

    @property
    def name(self) -> str:
        return "signature"

    def inspect(self, query: ParsedQuery) -> EngineVerdict:
        t0 = time.perf_counter()

        if self._is_bypassed(query.ast_fingerprint):
            return EngineVerdict(
                engine=self.name, action=Action.ALLOW, score=0.0,
                reasons=["allowlisted"], rule_ids=["ALLOWLIST"], latency_ms=0.0,
            )

        matched = [r for r in self.rules if self._match_rule(r, query)]
        action = Action.ALLOW
        score = 0.0
        rule_ids: list[str] = []
        reasons: list[str] = []

        if matched:
            rule_ids = [r.id for r in matched]
            reasons = [f"{r.id}: {r.name}" for r in matched]
            score = max(SEVERITY_SCORES.get(r.severity, 0.0) for r in matched)
            if any(r.severity in self._block_severities for r in matched):
                action = Action.BLOCK

        return EngineVerdict(
            engine=self.name, action=action, score=score,
            reasons=reasons, rule_ids=rule_ids,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
        )

    def _is_bypassed(self, fingerprint: str) -> bool:
        if not fingerprint:
            return False
        contains = getattr(self.bypass, "contains", None)
        if callable(contains):
            return bool(contains(fingerprint))
        try:
            return fingerprint in self.bypass
        except TypeError:
            return False

    def _match_rule(self, rule: Rule, query: ParsedQuery) -> bool:
        return any(self._match_condition(c, query) for c in rule.conditions)

    def _match_condition(self, condition: Condition, query: ParsedQuery) -> bool:
        if condition.has_union is not None and condition.has_union != query.has_union:
            return False
        if condition.has_stacked is not None and condition.has_stacked != query.has_stacked:
            return False
        if condition.has_comment is not None and condition.has_comment != query.has_comment:
            return False
        if condition.has_subquery is not None and condition.has_subquery != query.has_subquery:
            return False
        if condition.has_or is not None and condition.has_or != query.has_or:
            return False
        if condition.query_types is not None:
            if query.query_type.name not in {t.upper() for t in condition.query_types}:
                return False
        if condition.sql_contains is not None:
            raw_upper = query.raw_sql.upper()
            if not all(pat.upper() in raw_upper for pat in condition.sql_contains):
                return False
        if condition.min_literals is not None and query.literal_count < condition.min_literals:
            return False
        if condition.min_join_depth is not None and query.join_depth < condition.min_join_depth:
            return False
        if condition.table_blocklist is not None:
            blocked = {t.lower() for t in condition.table_blocklist}
            if not any(t in blocked for t in query.tables):
                return False
        return True
