import pytest

pytest.importorskip("sqlglot")

from sqlshield.engines.llm_policy import LLMPolicyEngine, LLMPolicyConfig
from sqlshield.enricher import Enricher
from sqlshield.parser import Parser
from sqlshield.types import Action, SessionInfo


@pytest.fixture
def parser():
    return Parser()


@pytest.fixture
def enricher():
    return Enricher()


@pytest.fixture
def engine():
    return LLMPolicyEngine()


def _parse(parser, enricher, sql, app_name="ai-agent/qwen"):
    pq = parser.parse(sql)
    enricher.enrich(pq, SessionInfo(user="demo", app_name=app_name))
    return pq


# ---- gating ---------------------------------------------------------------

def test_passthrough_when_not_ai_agent(engine, parser, enricher):
    pq = _parse(parser, enricher, "DROP TABLE users", app_name="psql")
    v  = engine.inspect(pq)
    assert v.action == Action.ALLOW
    assert v.rule_ids == []


def test_passthrough_when_no_context(engine, parser):
    pq = parser.parse("SELECT * FROM products LIMIT 10")
    # no enrichment -> no context -> engine must do nothing
    v = engine.inspect(pq)
    assert v.action == Action.ALLOW
    assert v.rule_ids == []


# ---- individual rules -----------------------------------------------------

def test_llm001_table_outside_allowlist(engine, parser, enricher):
    pq = _parse(parser, enricher,
                "SELECT id FROM secrets LIMIT 10")
    v = engine.inspect(pq)
    assert v.action == Action.BLOCK
    assert "LLM-001" in v.rule_ids


def test_llm002_blocks_mutation(engine, parser, enricher):
    pq = _parse(parser, enricher,
                "DELETE FROM products WHERE id = 1")
    v = engine.inspect(pq)
    assert v.action == Action.BLOCK
    assert "LLM-002" in v.rule_ids


def test_llm003_missing_limit(engine, parser, enricher):
    pq = _parse(parser, enricher, "SELECT name FROM products")
    v = engine.inspect(pq)
    assert v.action == Action.BLOCK
    assert "LLM-003" in v.rule_ids


def test_llm003_limit_too_large(engine, parser, enricher):
    pq = _parse(parser, enricher, "SELECT name FROM products LIMIT 9999")
    v = engine.inspect(pq)
    assert v.action == Action.BLOCK
    assert "LLM-003" in v.rule_ids


def test_llm004_users_without_where(engine, parser, enricher):
    pq = _parse(parser, enricher, "SELECT username FROM users LIMIT 5")
    v = engine.inspect(pq)
    assert v.action == Action.BLOCK
    assert "LLM-004" in v.rule_ids


def test_llm005_join_depth(engine, parser, enricher):
    sql = (
        "SELECT p.name FROM products p "
        "JOIN messages m ON m.id = p.id "
        "JOIN chat_logs c ON c.id = p.id "
        "JOIN users u ON u.id = p.id "
        "WHERE u.id = 1 LIMIT 10"
    )
    pq = _parse(parser, enricher, sql)
    v = engine.inspect(pq)
    assert "LLM-005" in v.rule_ids


def test_llm006_subquery_when_disabled(parser, enricher):
    eng = LLMPolicyEngine(LLMPolicyConfig(block_subqueries=True))
    pq  = _parse(parser, enricher,
                 "SELECT name FROM products WHERE id IN (SELECT id FROM products) LIMIT 10")
    v = eng.inspect(pq)
    assert "LLM-006" in v.rule_ids


def test_llm007_union(engine, parser, enricher):
    pq = _parse(parser, enricher,
                "SELECT name FROM products UNION SELECT username FROM users LIMIT 10")
    v = engine.inspect(pq)
    assert "LLM-007" in v.rule_ids
    assert v.action == Action.BLOCK


# ---- happy path -----------------------------------------------------------

def test_safe_select_passes(engine, parser, enricher):
    pq = _parse(parser, enricher,
                "SELECT name, price FROM products WHERE price < 100 LIMIT 10")
    v = engine.inspect(pq)
    assert v.action == Action.ALLOW
    assert v.rule_ids == []
