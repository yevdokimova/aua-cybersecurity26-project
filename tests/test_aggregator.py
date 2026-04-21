import pytest

from sqlshield.engines import BaseEngine
from sqlshield.types import Action, EngineVerdict, ParsedQuery
from sqlshield.verdict import Aggregator


class _StaticEngine(BaseEngine):
    def __init__(self, name, action=Action.ALLOW, score=0.0):
        self._n = name
        self._action = action
        self._score  = score

    @property
    def name(self): return self._n

    def inspect(self, query):
        return EngineVerdict(
            engine=self._n, action=self._action, score=self._score,
            reasons=[f"{self._n}-reason"], rule_ids=[f"{self._n.upper()}-1"],
            latency_ms=0.0,
        )


class _BrokenEngine(BaseEngine):
    @property
    def name(self): return "broken"
    def inspect(self, query):
        raise RuntimeError("boom")


def _query():
    return ParsedQuery(raw_sql="SELECT 1")


def test_enforce_blocks_when_any_engine_blocks():
    agg = Aggregator(engines=[
        _StaticEngine("a", Action.ALLOW, 0.0),
        _StaticEngine("b", Action.BLOCK, 1.0),
    ], mode="enforce")
    fv = agg.evaluate(_query())
    assert fv.action == Action.BLOCK
    assert fv.aggregate_score == 1.0
    assert {v.engine for v in fv.engine_verdicts} == {"a", "b"}


def test_monitor_records_but_never_blocks():
    agg = Aggregator(engines=[
        _StaticEngine("b", Action.BLOCK, 1.0),
    ], mode="monitor")
    fv = agg.evaluate(_query())
    assert fv.action == Action.ALLOW
    assert fv.aggregate_score == 1.0
    assert fv.engine_verdicts[0].action == Action.BLOCK


def test_learning_mode_never_blocks():
    agg = Aggregator(engines=[
        _StaticEngine("b", Action.BLOCK, 1.0),
    ], mode="learning")
    fv = agg.evaluate(_query())
    assert fv.action == Action.ALLOW


def test_engine_failure_isolated():
    agg = Aggregator(engines=[
        _BrokenEngine(),
        _StaticEngine("ok", Action.ALLOW, 0.2),
    ], mode="enforce")
    fv = agg.evaluate(_query())
    assert fv.action == Action.ALLOW
    names = {v.engine for v in fv.engine_verdicts}
    assert names == {"broken", "ok"}


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        Aggregator(engines=[], mode="bogus")
