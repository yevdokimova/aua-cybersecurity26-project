"""
Phase 2A — Context enrichment.

Attaches ``SessionInfo`` / ``QueryContext`` to a ``ParsedQuery`` before it
reaches the engines. The main job is inferring a ``source_tag`` (where did
this query come from: ORM, BI tool, AI agent, manual console, ...) so that
downstream engines can apply different policies.

The enricher does not raise: unknown values default to ``"unknown"`` so the
pipeline never breaks on enrichment errors.
"""

from __future__ import annotations

from .types import ParsedQuery, QueryContext, SessionInfo


# ---------------------------------------------------------------------------
# app_name → source_tag table
# ---------------------------------------------------------------------------
#
# Keys are matched as case-insensitive substrings of ``SessionInfo.app_name``
# so e.g. "Django/4.2" and "django-postgres" both resolve to "orm".

_SOURCE_TAG_RULES: list[tuple[tuple[str, ...], str]] = [
    (("django", "rails", "sqlalchemy", "prisma", "hibernate", "activerecord"),
     "orm"),
    (("tableau", "metabase", "looker", "grafana", "superset", "powerbi"),
     "bi-tool"),
    (("langchain", "openai", "ai-agent", "copilot", "llm", "anthropic"),
     "ai-agent"),
    (("psql", "pgadmin", "dbeaver", "datagrip", "tableplus"),
     "manual"),
]

_OVERRIDE_HEADER = "x-sqlshield-source"


def infer_source_tag(session: SessionInfo) -> str:
    """
    Infer a source tag from a session.

    Precedence:
    1. Explicit override in ``session.params`` under the
       ``x-sqlshield-source`` key (case-insensitive header form).
    2. Substring match against ``app_name`` using ``_SOURCE_TAG_RULES``.
    3. Fallback: ``"unknown"``.
    """
    # Explicit override always wins.
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
    """Attaches a ``QueryContext`` to a ``ParsedQuery`` in place."""

    def enrich(self, query: ParsedQuery, session: SessionInfo) -> ParsedQuery:
        tag = infer_source_tag(session)
        # Placeholder role inference: in a real deployment we would look the
        # role up from the database; for the demo we mirror the username.
        role = session.user or "anonymous"
        query.context = QueryContext(session=session, source_tag=tag, role=role)
        return query
