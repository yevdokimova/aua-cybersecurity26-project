from __future__ import annotations

from abc import ABC, abstractmethod

from ..types import EngineVerdict, ParsedQuery


class BaseEngine(ABC):

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def inspect(self, query: ParsedQuery) -> EngineVerdict: ...

    def healthy(self) -> bool:
        return True
