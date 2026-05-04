from sqlshield import audit
from sqlshield.types import (
    Action, EngineVerdict, ParsedQuery, QueryContext, QueryType, SessionInfo,
)


def _verdict():
    return EngineVerdict(
        engine="signature",
        action=Action.BLOCK,
        score=0.85,
        reasons=["SIG-001: UNION-based injection"],
        rule_ids=["SIG-001"],
        latency_ms=0.42,
    )


def _parsed():
    pq = ParsedQuery(
        raw_sql="SELECT 1 UNION SELECT 2",
        normalized_sql="SELECT ? UNION SELECT ?",
        ast_fingerprint="abc1234567890def",
        query_type=QueryType.SELECT,
        tables=["users"],
    )
    pq.context = QueryContext(
        session=SessionInfo(user="alice", database="demo",
                            app_name="psql", source_ip="1.2.3.4"),
        role="alice",
        source_tag="manual",
    )
    return pq


def test_write_and_read(tmp_path):
    audit.write("search", "SELECT 1", _parsed(),
                blocked=True, shield_enabled=True,
                engine_verdicts=[_verdict()])
    records = audit.read_all()
    assert len(records) == 1
    r = records[0]
    assert r["final_action"] == "BLOCKED"
    assert r["proxy_mode"]   == "enforce"
    assert r["source_tag"]   == "manual"
    assert r["user"]         == "alice"
    assert r["source_ip"]    == "1.2.3.4"
    assert r["engine_results"][0]["rule_ids"] == ["SIG-001"]
    assert r["total_latency_ms"] == 0.42


def test_shield_off_records_pass_through(tmp_path):
    pq = ParsedQuery(raw_sql="SELECT 1", query_type=QueryType.SELECT)
    audit.write("search", "SELECT 1", pq,
                blocked=False, shield_enabled=False)
    records = audit.read_all()
    assert records[0]["final_action"] == "SHIELD_OFF"
    assert records[0]["proxy_mode"]   == "monitor"
    assert records[0]["engine_results"] == []


def test_multi_engine_results(tmp_path):
    audit.write(
        "search", "SELECT 1", _parsed(),
        blocked=True, shield_enabled=True,
        engine_verdicts=[
            _verdict(),
            EngineVerdict(engine="anomaly", action=Action.ALLOW, score=0.0,
                          reasons=["learning"], rule_ids=["ANOM-LEARN"],
                          latency_ms=0.1),
        ],
    )
    r = audit.read_all()[0]
    assert [e["engine"] for e in r["engine_results"]] == ["signature", "anomaly"]
    assert abs(r["total_latency_ms"] - 0.52) < 1e-6
