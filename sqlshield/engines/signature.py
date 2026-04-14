from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..types import Action, EngineVerdict, ParsedQuery
from . import BaseEngine


# ---------------------------------------------------------------------------
# Severity → score mapping
# ---------------------------------------------------------------------------

SEVERITY_SCORES: dict[str, float] = {
    "critical": 1.0,
    "high":     0.85,
    "medium":   0.6,
    "low":      0.3,
}

# Minimum severity that causes BLOCK for each strictness level.
# Severities >= the floor block; severities below the floor are logged only.
_BLOCK_SEVERITIES: dict[str, frozenset[str]] = {
    "high":   frozenset({"critical", "high", "medium", "low"}),  # all block
    "medium": frozenset({"critical", "high", "medium"}),
    "low":    frozenset({"critical", "high"}),
}


# ---------------------------------------------------------------------------
# Condition — one matching criterion within a Rule
# ---------------------------------------------------------------------------

@dataclass
class Condition:
    """
    A single matching criterion.

    ALL non-None fields must match for the condition to fire (AND logic).
    None fields are ignored (wildcards).

    Fields
    ------
    has_union : bool | None
        Must equal query.has_union if set.
    has_stacked : bool | None
        Must equal query.has_stacked if set.
    has_comment : bool | None
        Must equal query.has_comment if set.
    has_subquery : bool | None
        Must equal query.has_subquery if set.
    has_or : bool | None
        Must equal query.has_or if set (OR inside WHERE clause only).
    query_types : list[str] | None
        query.query_type.name must appear in this list (case-insensitive).
    sql_contains : list[str] | None
        ALL strings in this list must appear in query.raw_sql (case-insensitive).
    min_literals : int | None
        query.literal_count must be >= this value.
    min_join_depth : int | None
        query.join_depth must be >= this value.
    table_blocklist : list[str] | None
        At least one of query.tables must appear in this list (case-insensitive).
    """
    has_union: bool | None              = None
    has_stacked: bool | None            = None
    has_comment: bool | None            = None
    has_subquery: bool | None           = None
    has_or: bool | None                 = None
    query_types: list[str] | None       = None
    sql_contains: list[str] | None      = None
    min_literals: int | None            = None
    min_join_depth: int | None          = None
    table_blocklist: list[str] | None   = None


# ---------------------------------------------------------------------------
# Rule — a named, severity-tagged detection rule
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    """
    A named detection rule with one or more matching conditions.

    A rule fires if ANY of its conditions matches (OR logic between conditions).
    Each condition uses AND logic between its own non-None fields.

    Fields
    ------
    id : str
        Short machine-readable identifier, e.g. "SIG-001".
    name : str
        Human-readable name displayed in block messages.
    description : str
        Detailed explanation of what the rule detects and why.
    severity : str
        One of "critical" | "high" | "medium" | "low".
    conditions : list[Condition]
        At least one condition must match for the rule to fire.
    """
    id: str
    name: str
    description: str
    severity: str
    conditions: list[Condition] = field(default_factory=list)


# ---------------------------------------------------------------------------
# DEFAULT_RULES — the 10 built-in detection rules
# ---------------------------------------------------------------------------

DEFAULT_RULES: list[Rule] = [

    # SIG-001 — UNION-based injection [critical]
    # -------------------------------------------------------------------------
    # Attack: SELECT name FROM products WHERE id = '' UNION SELECT password FROM users--
    # The legitimate application query never contains UNION.  The moment a UNION
    # appears in a SELECT statement, it was injected.
    # Evasion-proof: UN/**/ION and UnIoN both parse to the same exp.Union node.
    Rule(
        id="SIG-001",
        name="UNION-based injection",
        description=(
            "Detects UNION SELECT appended to a query to extract data from other tables. "
            "The application's intended query never contains UNION — its presence means "
            "the user input altered the query structure.  Evasion-resistant: all case "
            "and comment variants normalise to the same AST node."
        ),
        severity="critical",
        conditions=[
            Condition(has_union=True, query_types=["SELECT"]),
        ],
    ),

    # SIG-002 — Stacked queries [critical]
    # -------------------------------------------------------------------------
    # Attack: SELECT * FROM products WHERE id = ''; DROP TABLE products;--
    # Applications send exactly one statement per query.  Two statements means
    # the attacker injected a piggyback command after a semicolon.
    Rule(
        id="SIG-002",
        name="Stacked queries",
        description=(
            "Detects multiple SQL statements in a single query string. Applications "
            "send one statement per query. A semicolon followed by a second statement "
            "means the attacker injected a piggyback command (e.g. DROP TABLE, "
            "INSERT INTO, EXEC) after terminating the intended query."
        ),
        severity="critical",
        conditions=[
            Condition(has_stacked=True),
        ],
    ),

    # SIG-003 — Tautology attack [high]
    # -------------------------------------------------------------------------
    # Attack: SELECT * FROM users WHERE username = '' OR 1=1--
    # Injecting an always-true condition bypasses WHERE filters entirely.
    # We require BOTH an OR node in the WHERE clause AND a tautology string
    # pattern to reduce false positives on legitimate queries with OR.
    Rule(
        id="SIG-003",
        name="Tautology attack",
        description=(
            "Detects always-true conditions (OR 1=1, OR 'a'='a', etc.) injected into "
            "WHERE clauses. Used to bypass authentication checks or dump all rows from "
            "a table. Requires both an OR node in the WHERE clause AND a known tautology "
            "string to limit false positives on legitimate multi-condition queries."
        ),
        severity="high",
        conditions=[
            Condition(has_or=True, sql_contains=["1=1"]),
            Condition(has_or=True, sql_contains=["'='"]),
            Condition(has_or=True, sql_contains=["1='1"]),
            Condition(has_or=True, sql_contains=["''='"]),
            Condition(has_or=True, sql_contains=["' or 'a'='a"]),
        ],
    ),

    # SIG-004 — Comment-based obfuscation [medium]
    # -------------------------------------------------------------------------
    # Attack: SEL/**/ECT * FROM/**/users
    # Empty inline comments /**/ are inserted to break up keywords so they
    # pass naive regex filters.  Legitimate queries never contain /**/.
    Rule(
        id="SIG-004",
        name="Comment-based obfuscation",
        description=(
            "Detects empty inline comments (/**/) used to fragment SQL keywords and "
            "evade naive string-matching filters.  Example: SEL/**/ECT, UN/**/ION. "
            "Legitimate application queries never contain /**/ — its presence is a "
            "strong indicator of deliberate obfuscation."
        ),
        severity="medium",
        conditions=[
            Condition(has_comment=True, sql_contains=["/**/"]),
        ],
    ),

    # SIG-005 — System table access [high]
    # -------------------------------------------------------------------------
    # Attack: SELECT table_name FROM information_schema.tables
    # Attackers enumerate schema structure by querying system catalog tables.
    # No legitimate application query should touch these tables directly.
    Rule(
        id="SIG-005",
        name="System table access",
        description=(
            "Detects queries targeting database system catalog and metadata tables. "
            "Attackers enumerate table names, column names, and user credentials by "
            "reading information_schema, pg_shadow, pg_authid, etc.  Legitimate "
            "application code uses ORM metadata or migrations — never raw catalog queries."
        ),
        severity="high",
        conditions=[
            Condition(table_blocklist=[
                "information_schema",
                "pg_catalog",
                "pg_shadow",
                "pg_authid",
                "pg_user",
                "pg_roles",
                "mysql.user",
                "sys.objects",
                "sysobjects",
                "sqlite_master",
            ]),
        ],
    ),

    # SIG-006 — Excessive literal injection [medium]
    # -------------------------------------------------------------------------
    # Attack: SELECT * FROM products WHERE id = 1 OR 2=2 OR 3=3 OR 'x'='x'
    # Automated tools like sqlmap spray many test conditions in a single query.
    # A high literal count combined with OR is a reliable signal.
    Rule(
        id="SIG-006",
        name="Excessive literal injection",
        description=(
            "Detects queries with an unusually high number of literal values combined "
            "with OR conditions — the hallmark of automated injection tools (sqlmap, "
            "Havij, etc.) that spray test payloads.  Legitimate queries rarely have "
            "more than 4-5 literals in a single WHERE clause."
        ),
        severity="medium",
        conditions=[
            Condition(min_literals=5, has_or=True),
        ],
    ),

    # SIG-007 — Sleep/benchmark injection [critical]
    # -------------------------------------------------------------------------
    # Attack: SELECT * FROM users WHERE id = 1 AND SLEEP(5)
    # Time-based blind injection extracts data bit-by-bit by measuring
    # response delays.  Each database has its own delay function.
    Rule(
        id="SIG-007",
        name="Sleep/benchmark injection",
        description=(
            "Detects time-based blind SQL injection using database-specific delay "
            "functions.  The attacker extracts data one bit at a time by observing "
            "response timing.  Covers MySQL SLEEP()/BENCHMARK(), PostgreSQL pg_sleep(), "
            "and SQL Server WAITFOR DELAY."
        ),
        severity="critical",
        conditions=[
            Condition(sql_contains=["sleep("]),
            Condition(sql_contains=["benchmark("]),
            Condition(sql_contains=["pg_sleep("]),
            Condition(sql_contains=["waitfor delay"]),
        ],
    ),

    # SIG-008 — File operation injection [critical]
    # -------------------------------------------------------------------------
    # Attack: SELECT LOAD_FILE('/etc/passwd')
    # Attack: SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/shell.php'
    # File I/O via SQL escalates from database compromise to full server compromise.
    Rule(
        id="SIG-008",
        name="File operation injection",
        description=(
            "Detects SQL that reads or writes files on the database server filesystem. "
            "LOAD_FILE() reads arbitrary files (e.g. /etc/passwd, source code). "
            "INTO OUTFILE / INTO DUMPFILE writes attacker-controlled content (e.g. PHP "
            "web shells).  These escalate database compromise to full server compromise."
        ),
        severity="critical",
        conditions=[
            Condition(sql_contains=["load_file("]),
            Condition(sql_contains=["into outfile"]),
            Condition(sql_contains=["into dumpfile"]),
            Condition(sql_contains=["copy from"]),
        ],
    ),

    # SIG-009 — Boolean-based blind injection [high]
    # -------------------------------------------------------------------------
    # Attack: SELECT * FROM products WHERE id=1 AND (SELECT CASE WHEN
    #           (SUBSTRING(username,1,1)='a') THEN 1 ELSE 0 END FROM users)=1
    # Requires all three signals together to minimise false positives:
    # a CASE WHEN subquery combined with OR is very rarely legitimate code.
    Rule(
        id="SIG-009",
        name="Boolean-based blind injection",
        description=(
            "Detects blind injection using conditional logic (CASE WHEN) inside a "
            "subquery combined with OR conditions.  The attacker reconstructs secret "
            "values one character at a time by observing whether the query returns "
            "rows.  Requires all three signals (subquery + OR + CASE WHEN) together "
            "to avoid false positives on legitimate conditional queries."
        ),
        severity="high",
        conditions=[
            Condition(has_subquery=True, has_or=True, sql_contains=["case when"]),
        ],
    ),

    # SIG-010 — Error-based extraction [high]
    # -------------------------------------------------------------------------
    # Attack: SELECT EXTRACTVALUE(1, CONCAT(0x7e, (SELECT password FROM users)))
    # Forces the database to include sensitive data in an error message that
    # the attacker can read from the HTTP response or error log.
    Rule(
        id="SIG-010",
        name="Error-based extraction",
        description=(
            "Detects attacks that force the database to embed sensitive values into "
            "error messages.  EXTRACTVALUE() and UPDATEXML() cause XML parsing errors "
            "whose message includes the injected expression result.  CONVERT(INT,...) "
            "causes a type-conversion error that leaks string values."
        ),
        severity="high",
        conditions=[
            Condition(sql_contains=["extractvalue("]),
            Condition(sql_contains=["updatexml("]),
            Condition(sql_contains=["convert(int,"]),
        ],
    ),
]


# ---------------------------------------------------------------------------
# SignatureEngine
# ---------------------------------------------------------------------------

class SignatureEngine(BaseEngine):
    """
    AST-pattern signature engine — the workhorse of the detection pipeline.

    Evaluates each query against DEFAULT_RULES (or a custom rule list) and
    returns BLOCK as soon as any rule above the strictness floor matches.
    Sub-millisecond for non-matching queries; a few hundred microseconds for
    matching ones.

    Parameters
    ----------
    rules : list[Rule] | None
        Rule library to use.  Defaults to DEFAULT_RULES.  Pass a custom list
        to test specific rules in isolation.
    bypass_fingerprints : set[str] | None
        AST fingerprints that unconditionally bypass all rules (allowlist).
        Useful for known-safe queries that trigger false positives.
    strictness : str
        Severity floor: "high" (block all), "medium" (block medium+),
        "low" (block high+ only).  Default "medium".
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        bypass_fingerprints: set[str] | None = None,
        strictness: str = "medium",
    ) -> None:
        self.rules = rules if rules is not None else DEFAULT_RULES
        self.bypass = bypass_fingerprints or set()
        self.strictness = strictness
        # Pre-compute the blocking severity set for this engine instance.
        self._block_severities = _BLOCK_SEVERITIES.get(
            strictness, _BLOCK_SEVERITIES["medium"]
        )

    @property
    def name(self) -> str:
        return "signature"

    # ------------------------------------------------------------------
    # inspect — main entry point
    # ------------------------------------------------------------------

    def inspect(self, query: ParsedQuery) -> EngineVerdict:
        """
        Evaluate *query* against the rule library and return a verdict.

        Steps
        -----
        1. Fast-path bypass: if the query's AST fingerprint is in the
           allowlist, return ALLOW immediately.
        2. Rule evaluation: match each rule against the query.
        3. Decision: if any *blocking-severity* rule matched → BLOCK.
           If only sub-floor rules matched → ALLOW (but record them).
        4. Score: the score of the highest-severity matched rule.
        5. Latency: wall-clock time spent in this engine.
        """
        t0 = time.perf_counter()

        # Step 1 — bypass fast path
        if query.ast_fingerprint in self.bypass:
            return EngineVerdict(
                engine=self.name,
                action=Action.ALLOW,
                score=0.0,
                reasons=[],
                rule_ids=[],
                latency_ms=0.0,
            )

        # Step 2 — evaluate all rules
        matched_rules: list[Rule] = []
        for rule in self.rules:
            if self._match_rule(rule, query):
                matched_rules.append(rule)

        # Step 3 & 4 — determine action and score
        action = Action.ALLOW
        score = 0.0
        rule_ids: list[str] = []
        reasons: list[str] = []

        if matched_rules:
            # All matched rules are recorded regardless of blocking floor.
            for rule in matched_rules:
                rule_ids.append(rule.id)
                reasons.append(f"{rule.id}: {rule.name}")

            # Score = highest severity score among all matched rules.
            score = max(SEVERITY_SCORES.get(r.severity, 0.0) for r in matched_rules)

            # Action is BLOCK only if at least one matched rule is at or
            # above the strictness floor.
            blocking = [r for r in matched_rules if r.severity in self._block_severities]
            if blocking:
                action = Action.BLOCK

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return EngineVerdict(
            engine=self.name,
            action=action,
            score=score,
            reasons=reasons,
            rule_ids=rule_ids,
            latency_ms=latency_ms,
        )

    # ------------------------------------------------------------------
    # Rule / condition matching
    # ------------------------------------------------------------------

    def _match_rule(self, rule: Rule, query: ParsedQuery) -> bool:
        """
        Return True if ANY of the rule's conditions matches *query*.

        OR logic: the rule fires on the first matching condition.
        """
        return any(self._match_condition(c, query) for c in rule.conditions)

    def _match_condition(self, condition: Condition, query: ParsedQuery) -> bool:
        """
        Return True if ALL non-None fields of *condition* match *query*.

        AND logic: every non-None field must match; a single mismatch
        short-circuits to False.
        """
        # ---- boolean structural flags ----------------------------------
        if condition.has_union is not None:
            if condition.has_union != query.has_union:
                return False

        if condition.has_stacked is not None:
            if condition.has_stacked != query.has_stacked:
                return False

        if condition.has_comment is not None:
            if condition.has_comment != query.has_comment:
                return False

        if condition.has_subquery is not None:
            if condition.has_subquery != query.has_subquery:
                return False

        if condition.has_or is not None:
            if condition.has_or != query.has_or:
                return False

        # ---- query type whitelist --------------------------------------
        if condition.query_types is not None:
            allowed = {t.upper() for t in condition.query_types}
            if query.query_type.name not in allowed:
                return False

        # ---- substring checks (case-insensitive, ALL must be present) --
        if condition.sql_contains is not None:
            raw_upper = query.raw_sql.upper()
            if not all(pat.upper() in raw_upper for pat in condition.sql_contains):
                return False

        # ---- numeric thresholds ----------------------------------------
        if condition.min_literals is not None:
            if query.literal_count < condition.min_literals:
                return False

        if condition.min_join_depth is not None:
            if query.join_depth < condition.min_join_depth:
                return False

        # ---- table blocklist (ANY table in query must be in the list) --
        if condition.table_blocklist is not None:
            blocked_lower = {t.lower() for t in condition.table_blocklist}
            if not any(t in blocked_lower for t in query.tables):
                return False

        # All non-None fields matched
        return True