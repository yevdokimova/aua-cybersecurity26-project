"""
Phase 2D — Verdict aggregator.

Runs every registered engine over a parsed query and merges the results
into a single ``FinalVerdict``. Engines run in parallel when there is more
than one, but exceptions in any engine are isolated so a broken engine
can never take the pipeline down.

Three operating modes
---------------------
- ``enforce``   — engine verdicts decide. Any BLOCK → BLOCK.
- ``monitor``   — always ALLOW; engine verdicts are still recorded.
- ``learning``  — always ALLOW; intended for the anomaly baseline phase.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import time

from .engines import BaseEngine
from .types import Action, EngineVerdict, ParsedQuery

logger = logging.getLogger(__name__)

_VALID_MODES = ("enforce", "monitor", "learning")


@dataclass
class FinalVerdict:
    action: Action
    engine_verdicts: list[EngineVerdict] = field(default_factory=list)
    aggregate_score: float               = 0.0
    latency_ms: float                    = 0.0
    mode: str                            = "enforce"


class Aggregator:
    def __init__(self, engines: list[BaseEngine], mode: str = "enforce") -> None:
        if mode not in _VALID_MODES:
            raise ValueError(f"mode must be one of {_VALID_MODES}, got {mode!r}")
        self.engines = list(engines)
        self.mode    = mode

    # ------------------------------------------------------------------

    def evaluate(self, query: ParsedQuery) -> FinalVerdict:
        t0 = time.perf_counter()
        verdicts = self._run_engines(query)

        # Aggregate score = max of all engine scores (matches signature
        # engine's own aggregation, so the value is comparable).
        aggregate = max((v.score for v in verdicts), default=0.0)

        any_block = any(v.action == Action.BLOCK for v in verdicts)
        if self.mode == "enforce" and any_block:
            action = Action.BLOCK
        else:
            action = Action.ALLOW

        return FinalVerdict(
            action=action,
            engine_verdicts=verdicts,
            aggregate_score=aggregate,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            mode=self.mode,
        )

    # ------------------------------------------------------------------

    def _run_engines(self, query: ParsedQuery) -> list[EngineVerdict]:
        if not self.engines:
            return []
        if len(self.engines) == 1:
            return [self._safe_inspect(self.engines[0], query)]
        with ThreadPoolExecutor(max_workers=len(self.engines)) as pool:
            futures = [pool.submit(self._safe_inspect, e, query) for e in self.engines]
            return [f.result() for f in futures]

    @staticmethod
    def _safe_inspect(engine: BaseEngine, query: ParsedQuery) -> EngineVerdict:
        try:
            return engine.inspect(query)
        except Exception as exc:  # noqa: BLE001 — engine isolation
            logger.exception("engine %s crashed: %s", engine.name, exc)
            return EngineVerdict(
                engine=getattr(engine, "name", "unknown"),
                action=Action.ALLOW,
                score=0.0,
                reasons=[f"engine error: {exc}"],
                rule_ids=[],
                latency_ms=0.0,
            )
