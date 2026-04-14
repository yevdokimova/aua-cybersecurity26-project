from __future__ import annotations

import hashlib
import re
import logging

import sqlglot
import sqlglot.expressions as exp
from sqlglot.errors import ErrorLevel

from .types import ParsedQuery, QueryType

logger = logging.getLogger(__name__)

_AST_TYPE_MAP: list[tuple[type, QueryType]] = [
    (exp.Select,       QueryType.SELECT),
    (exp.Union,        QueryType.SELECT),
    (exp.Intersect,    QueryType.SELECT),
    (exp.Except,       QueryType.SELECT),
    (exp.Insert,       QueryType.INSERT),
    (exp.Update,       QueryType.UPDATE),
    (exp.Delete,       QueryType.DELETE),
    (exp.Create,       QueryType.DDL),
    (exp.Alter,        QueryType.DDL),
    (exp.Drop,         QueryType.DDL),
    (exp.TruncateTable,QueryType.DDL),
    (exp.Grant,        QueryType.DCL),
    (exp.Revoke,       QueryType.DCL),
    (exp.Command,      QueryType.ADMIN),
    (exp.Transaction,  QueryType.ADMIN),
    (exp.Use,          QueryType.ADMIN),
]

_KEYWORD_MAP: dict[str, QueryType] = {
    "select": QueryType.SELECT, "insert": QueryType.INSERT,
    "update": QueryType.UPDATE, "delete": QueryType.DELETE,
    "create": QueryType.DDL,    "alter":  QueryType.DDL,
    "drop":   QueryType.DDL,    "truncate": QueryType.DDL,
    "grant":  QueryType.DCL,    "revoke": QueryType.DCL,
    "vacuum": QueryType.ADMIN,  "analyze": QueryType.ADMIN,
    "set":    QueryType.ADMIN,  "show":   QueryType.ADMIN,
    "explain":QueryType.ADMIN,
}


class Parser:
    def __init__(self, dialect: str = "postgres") -> None:
        self.dialect = dialect

    def parse(self, raw_sql: str) -> ParsedQuery:
        stripped = raw_sql.strip()
        if not stripped:
            return ParsedQuery(raw_sql=raw_sql, query_type=QueryType.UNKNOWN)
        pq = ParsedQuery(raw_sql=raw_sql)
        pq.has_comment = "--" in raw_sql or "/*" in raw_sql
        try:
            return self._ast_parse(pq)
        except Exception as exc:
            logger.debug("sqlglot parse error — falling back to regex: %s", exc)
            return self._fallback_parse(pq)

    def _ast_parse(self, pq: ParsedQuery) -> ParsedQuery:
        stmts = sqlglot.parse(pq.raw_sql, dialect=self.dialect, error_level=ErrorLevel.IGNORE)
        stmts = [s for s in stmts if s is not None]
        if not stmts:
            return self._fallback_parse(pq)

        stmt = stmts[0]
        pq.query_type  = self._detect_query_type(stmt, pq.raw_sql)
        pq.has_stacked = len(stmts) > 1
        pq.normalized_sql  = self._normalize(stmt)
        pq.ast_fingerprint = hashlib.sha256(
            pq.normalized_sql.encode("utf-8", errors="replace")
        ).hexdigest()[:16]

        seen_tables: set[str] = set()
        for node in stmt.find_all(exp.Table):
            name = node.name or ""
            if not name:
                continue
            if node.db:
                name = f"{node.db}.{name}"
            seen_tables.add(name.lower())
        pq.tables = sorted(seen_tables)

        pq.has_union    = isinstance(stmt, (exp.Union, exp.Intersect, exp.Except)) or (
                          stmt.find(exp.Union, exp.Intersect, exp.Except) is not None)
        pq.has_subquery = stmt.find(exp.Subquery) is not None

        where_node = stmt.find(exp.Where)
        if where_node is not None:
            pq.has_or = where_node.find(exp.Or) is not None

        pq.join_depth    = len(list(stmt.find_all(exp.Join)))
        pq.literal_count = len(list(stmt.find_all(exp.Literal)))
        return pq

    def _normalize(self, stmt: exp.Expression) -> str:
        try:
            normalized = stmt.copy()
            for lit in list(normalized.find_all(exp.Literal)):
                lit.replace(exp.Placeholder())
            return normalized.sql(dialect=self.dialect, pretty=False)
        except Exception:
            return stmt.sql(dialect=self.dialect, pretty=False)

    def _detect_query_type(self, stmt: exp.Expression, raw_sql: str) -> QueryType:
        for ast_type, qt in _AST_TYPE_MAP:
            if isinstance(stmt, ast_type):
                return qt
        first = raw_sql.strip().split()[0].lower() if raw_sql.strip() else ""
        return _KEYWORD_MAP.get(first, QueryType.UNKNOWN)

    def _fallback_parse(self, pq: ParsedQuery) -> ParsedQuery:
        raw   = pq.raw_sql
        upper = raw.upper()

        first = raw.strip().split()[0].lower() if raw.strip() else ""
        pq.query_type = _KEYWORD_MAP.get(first, QueryType.UNKNOWN)

        norm = re.sub(r"'(?:[^'\\]|\\.)*'", "?", raw)
        norm = re.sub(r"\b\d+\.?\d*\b", "?", norm)
        norm = re.sub(r"\s+", " ", norm).strip()
        pq.normalized_sql  = norm
        pq.ast_fingerprint = hashlib.sha256(
            norm.encode("utf-8", errors="replace")
        ).hexdigest()[:16]

        seen: set[str] = set()
        for pat in [r"(?i)\bFROM\s+(\w+)", r"(?i)\bJOIN\s+(\w+)",
                    r"(?i)\bINTO\s+(\w+)", r"(?i)\bUPDATE\s+(\w+)"]:
            for m in re.finditer(pat, raw):
                seen.add(m.group(1).lower())
        pq.tables = sorted(seen)

        pq.has_union    = "UNION" in upper
        pq.has_or       = " OR " in upper
        pq.has_subquery = upper.count("SELECT") > 1
        pq.has_stacked  = ";" in raw.strip().rstrip(";").rstrip()
        pq.join_depth   = upper.count("JOIN")

        string_lits  = len(re.findall(r"'(?:[^'\\]|\\.)*'", raw))
        numeric_lits = len(re.findall(r"\b\d+\.?\d*\b", raw))
        pq.literal_count = string_lits + numeric_lits
        return pq
