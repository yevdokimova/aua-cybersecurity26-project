import pytest

pytest.importorskip("sqlglot")

from sqlshield.engines.signature import (
    SignatureEngine, Rule, Condition, DEFAULT_RULES,
)
from sqlshield.parser import Parser
from sqlshield.types import Action


RULES = DEFAULT_RULES + [
    Rule(
        id="SIG-011",
        name="Comment-based injection",
        description="-- in a SELECT.",
        severity="high",
        conditions=[Condition(has_comment=True, query_types=["SELECT"])],
    ),
]


@pytest.fixture
def engine():
    return SignatureEngine(rules=RULES, strictness="medium")


@pytest.fixture
def parser():
    return Parser()


def _ids(verdict):
    return set(verdict.rule_ids)


# ---- positive cases: rule fires ------------------------------------------

def test_sig001_union(engine, parser):
    sql = "SELECT name FROM products WHERE id = 1 UNION SELECT password FROM users"
    v = engine.inspect(parser.parse(sql))
    assert v.action == Action.BLOCK
    assert "SIG-001" in _ids(v)


def test_sig002_stacked(engine, parser):
    sql = "SELECT * FROM products WHERE id = 1; DROP TABLE products;"
    v = engine.inspect(parser.parse(sql))
    assert v.action == Action.BLOCK
    assert "SIG-002" in _ids(v)


def test_sig003_tautology(engine, parser):
    sql = "SELECT * FROM users WHERE username = 'x' OR 1=1"
    v = engine.inspect(parser.parse(sql))
    assert v.action == Action.BLOCK
    assert "SIG-003" in _ids(v)


def test_sig004_comment_obfuscation(engine, parser):
    sql = "SELECT/**/* FROM products WHERE id = 1"
    v = engine.inspect(parser.parse(sql))
    assert "SIG-004" in _ids(v)


def test_sig005_system_table(engine, parser):
    sql = "SELECT table_name FROM information_schema.tables"
    v = engine.inspect(parser.parse(sql))
    assert v.action == Action.BLOCK
    assert "SIG-005" in _ids(v)


def test_sig005_system_table_bare(engine, parser):
    """SQLite-style: schema is implicit, table name appears bare."""
    sql = "SELECT name FROM sqlite_master"
    v = engine.inspect(parser.parse(sql))
    assert v.action == Action.BLOCK
    assert "SIG-005" in _ids(v)


def test_sig007_sleep(engine, parser):
    sql = "SELECT * FROM users WHERE id = 1 AND pg_sleep(5)"
    v = engine.inspect(parser.parse(sql))
    assert v.action == Action.BLOCK
    assert "SIG-007" in _ids(v)


def test_sig008_file_op(engine, parser):
    sql = "SELECT load_file('/etc/passwd')"
    v = engine.inspect(parser.parse(sql))
    assert v.action == Action.BLOCK
    assert "SIG-008" in _ids(v)


def test_sig011_auth_bypass_comment(engine, parser):
    sql = "SELECT * FROM users WHERE username = 'admin'--' AND password = 'x'"
    v = engine.inspect(parser.parse(sql))
    assert v.action == Action.BLOCK
    assert "SIG-011" in _ids(v)


# ---- negative cases: benign queries pass ---------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT id, name, price FROM products WHERE name LIKE '%Laptop%'",
    "SELECT * FROM users WHERE username = 'alice' AND password = 'pass123'",
    "INSERT INTO messages (name, email, message) VALUES ('a', 'b@c.d', 'hi')",
    "INSERT INTO chat_logs (user_message) VALUES ('hello there')",
])
def test_benign_queries_allowed(engine, parser, sql):
    v = engine.inspect(parser.parse(sql))
    assert v.action == Action.ALLOW, f"unexpectedly blocked: {v.rule_ids}"
    assert v.score == 0.0


# ---- allowlist bypass ----------------------------------------------------

def test_allowlist_bypass_with_set(parser):
    sql = "SELECT * FROM users WHERE username = 'x' OR 1=1"
    pq = parser.parse(sql)
    eng = SignatureEngine(rules=RULES, bypass_fingerprints={pq.ast_fingerprint})
    v = eng.inspect(pq)
    assert v.action == Action.ALLOW
    assert v.rule_ids == ["ALLOWLIST"]


def test_allowlist_bypass_with_store(parser):
    from sqlshield.allowlist import AllowlistStore, AllowlistEntry

    sql = "SELECT * FROM users WHERE username = 'x' OR 1=1"
    pq = parser.parse(sql)
    store = AllowlistStore()
    store.add(AllowlistEntry(fingerprint=pq.ast_fingerprint, reason="test"))
    eng = SignatureEngine(rules=RULES, bypass_fingerprints=store)
    v = eng.inspect(pq)
    assert v.action == Action.ALLOW
    assert v.rule_ids == ["ALLOWLIST"]


# ---- strictness floor ----------------------------------------------------

def test_strictness_low_only_blocks_high_and_critical(parser):
    # SIG-006 is medium; with strictness=low it should still match but
    # not block.
    sql = "SELECT * FROM products WHERE id=1 OR 2=2 OR 3=3 OR 4=4 OR 5=5"
    eng = SignatureEngine(rules=DEFAULT_RULES, strictness="low")
    v = eng.inspect(parser.parse(sql))
    assert "SIG-006" in v.rule_ids
    assert v.action == Action.ALLOW
