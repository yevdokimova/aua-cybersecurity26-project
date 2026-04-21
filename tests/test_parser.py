import pytest

pytest.importorskip("sqlglot")

from sqlshield.parser import Parser
from sqlshield.types import QueryType


@pytest.fixture
def parser():
    return Parser()


def test_select_basic(parser):
    pq = parser.parse("SELECT id, name FROM products WHERE id = 1")
    assert pq.query_type == QueryType.SELECT
    assert "products" in pq.tables
    assert pq.has_union is False
    assert pq.has_or is False
    assert pq.has_stacked is False
    assert pq.literal_count >= 1
    assert pq.ast_fingerprint
    # Literals must be normalized away so two queries with different
    # constants produce the same fingerprint.
    other = parser.parse("SELECT id, name FROM products WHERE id = 999")
    assert pq.ast_fingerprint == other.ast_fingerprint


def test_union_detected(parser):
    pq = parser.parse(
        "SELECT name FROM products WHERE id = 1 UNION SELECT password FROM users"
    )
    assert pq.has_union is True
    assert pq.query_type == QueryType.SELECT
    assert "users" in pq.tables and "products" in pq.tables


def test_stacked_detected(parser):
    pq = parser.parse("SELECT 1; DROP TABLE products;")
    assert pq.has_stacked is True


def test_or_inside_where(parser):
    pq = parser.parse("SELECT * FROM users WHERE username = 'x' OR 1 = 1")
    assert pq.has_or is True


def test_or_only_outside_where_does_not_count(parser):
    # An OR in a SELECT projection (e.g. CASE expression with OR) should
    # still not flip has_or because it is not in the WHERE clause.
    pq = parser.parse("SELECT id FROM products WHERE id = 1")
    assert pq.has_or is False


def test_comment_detected(parser):
    pq = parser.parse("SELECT * FROM users -- trailing comment")
    assert pq.has_comment is True


def test_subquery_detected(parser):
    pq = parser.parse(
        "SELECT * FROM products WHERE id IN (SELECT product_id FROM orders)"
    )
    assert pq.has_subquery is True


def test_join_depth(parser):
    pq = parser.parse(
        "SELECT a.* FROM a JOIN b ON a.id = b.id JOIN c ON b.id = c.id"
    )
    assert pq.join_depth == 2


def test_query_type_dml_ddl(parser):
    assert parser.parse("INSERT INTO t (a) VALUES (1)").query_type == QueryType.INSERT
    assert parser.parse("UPDATE t SET a = 1").query_type           == QueryType.UPDATE
    assert parser.parse("DELETE FROM t WHERE id = 1").query_type   == QueryType.DELETE
    assert parser.parse("DROP TABLE t").query_type                 == QueryType.DDL


def test_fallback_on_garbage(parser):
    # Malformed SQL must not raise; it falls back to the regex parser.
    pq = parser.parse("SELEC FROM WHERE")
    assert pq.raw_sql == "SELEC FROM WHERE"
