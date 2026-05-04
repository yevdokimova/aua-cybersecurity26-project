from __future__ import annotations

from .types import ParsedQuery, QueryContext, SessionInfo


_SOURCE_TAG_RULES: list[tuple[tuple[str, ...], str]] = [
    (("django", "rails", "sqlalchemy", "prisma", "hibernate", "activerecord"), "orm"),
    (("tableau", "metabase", "looker", "grafana", "superset", "powerbi"), "bi-tool"),
    (("langchain", "openai", "ai-agent", "copilot", "llm", "anthropic"), "ai-agent"),
    (("psql", "pgadmin", "dbeaver", "datagrip", "tableplus"), "manual"),
]

_OVERRIDE_HEADER = "x-sqlshield-source"


def infer_source_tag(session: SessionInfo) -> str:
    for key, value in session.params.items():
        if key.lower() == _OVERRIDE_HEADER and value:
            return str(value).lower()
    name = (session.app_name or "").lower()
    if not name:
        return "unknown"
    for needles, tag in _SOURCE_TAG_RULES:
        if any(n in name for n in needles):
            return tag
    return "unknown"


class Enricher:
    def enrich(self, query: ParsedQuery, session: SessionInfo) -> ParsedQuery:
        tag = infer_source_tag(session)
        role = session.user or "anonymous"
        query.context = QueryContext(session=session, source_tag=tag, role=role)
        return query
