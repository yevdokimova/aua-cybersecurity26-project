import pytest

from sqlshield.enricher import Enricher, infer_source_tag
from sqlshield.types import ParsedQuery, SessionInfo


@pytest.mark.parametrize("app_name,expected", [
    ("Django/4.2",            "orm"),
    ("sqlalchemy",            "orm"),
    ("Tableau Desktop 2023",  "bi-tool"),
    ("metabase-server",       "bi-tool"),
    ("langchain-postgres",    "ai-agent"),
    ("openai-tools",          "ai-agent"),
    ("psql",                  "manual"),
    ("DBeaver/24.0",          "manual"),
    ("",                      "unknown"),
    ("totally-custom-app",    "unknown"),
])
def test_source_tag_inference(app_name, expected):
    assert infer_source_tag(SessionInfo(app_name=app_name)) == expected


def test_explicit_override_wins():
    s = SessionInfo(
        app_name="psql",
        params={"x-sqlshield-source": "ai-agent"},
    )
    assert infer_source_tag(s) == "ai-agent"


def test_enricher_attaches_context():
    pq = ParsedQuery(raw_sql="SELECT 1")
    s = SessionInfo(user="alice", app_name="Django/4.2", source_ip="10.0.0.1")
    Enricher().enrich(pq, s)

    assert pq.context is not None
    assert pq.context.source_tag == "orm"
    assert pq.context.role == "alice"
    assert pq.context.session.source_ip == "10.0.0.1"
