from sqlshield.engines.anomaly import AnomalyEngine
from sqlshield.types import (
    Action, ParsedQuery, QueryContext, QueryType, SessionInfo,
)


def _q(raw, fingerprint, query_type=QueryType.SELECT, tables=("products",),
       literal_count=1, join_depth=0, user="alice"):
    pq = ParsedQuery(
        raw_sql=raw,
        normalized_sql=raw,
        ast_fingerprint=fingerprint,
        query_type=query_type,
        tables=list(tables),
        literal_count=literal_count,
        join_depth=join_depth,
    )
    pq.context = QueryContext(
        session=SessionInfo(user=user),
        role=user,
        source_tag="manual",
    )
    return pq


def test_learning_phase_always_allows(tmp_path):
    eng = AnomalyEngine(learning_queries=5,
                        store_path=str(tmp_path / "b.json"))
    for i in range(5):
        v = eng.inspect(_q(f"SELECT {i}", f"fp{i % 3}"))
        assert v.action == Action.ALLOW
        assert "ANOM-LEARN" in v.rule_ids


def test_novel_fingerprint_post_learning(tmp_path):
    eng = AnomalyEngine(learning_queries=3,
                        store_path=str(tmp_path / "b.json"))
    # Three queries of the same shape leave learning mode.
    for _ in range(3):
        eng.inspect(_q("SELECT * FROM products WHERE id = ?", "shape-A"))
    v = eng.inspect(_q("SELECT * FROM users WHERE password = ?", "shape-B",
                       tables=("products",)))
    assert v.action == Action.BLOCK
    assert "ANOM-001" in v.rule_ids


def test_novel_table_post_learning(tmp_path):
    eng = AnomalyEngine(learning_queries=3,
                        store_path=str(tmp_path / "b.json"))
    for _ in range(3):
        eng.inspect(_q("SELECT * FROM products", "p", tables=("products",)))
    # Same fingerprint, new table.
    v = eng.inspect(_q("SELECT * FROM products", "p",
                       tables=("products", "users")))
    assert "ANOM-002" in v.rule_ids


def test_first_mutation_post_learning(tmp_path):
    eng = AnomalyEngine(learning_queries=3,
                        store_path=str(tmp_path / "b.json"))
    for _ in range(3):
        eng.inspect(_q("SELECT *", "p", query_type=QueryType.SELECT))
    v = eng.inspect(_q("UPDATE products SET price = 1", "p2",
                       query_type=QueryType.UPDATE,
                       tables=("products",)))
    assert v.action == Action.BLOCK
    assert "ANOM-003" in v.rule_ids


def test_reset_baseline(tmp_path):
    eng = AnomalyEngine(learning_queries=2,
                        store_path=str(tmp_path / "b.json"))
    for _ in range(2):
        eng.inspect(_q("SELECT *", "p"))
    assert eng.reset_baseline("alice") is True
    # After reset, the user is back in learning mode.
    v = eng.inspect(_q("SELECT * FROM other", "p2", tables=("other",)))
    assert "ANOM-LEARN" in v.rule_ids


def test_persistence_round_trip(tmp_path):
    path = str(tmp_path / "b.json")
    eng = AnomalyEngine(learning_queries=10, store_path=path)
    eng.inspect(_q("SELECT 1", "p1"))
    eng.inspect(_q("SELECT 2", "p2"))

    eng2 = AnomalyEngine(learning_queries=10, store_path=path)
    exported = eng2.export_baselines()
    assert any("alice" in k for k in exported.keys())
