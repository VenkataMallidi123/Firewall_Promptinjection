"""Per-scan state passed to every stage, plus the multi-turn Session."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import AttackType, Source, Trust


@dataclass
class Turn:
    text: str
    risk: float
    types: dict[str, float]


@dataclass
class Session:
    """Conversation memory, so attacks spread across several turns can be caught."""
    turns: list[Turn] = field(default_factory=list)

    def recent(self, n: int) -> list[Turn]:
        return self.turns[-n:]

    def add(self, text: str, risk: float, types: dict[str, float]) -> None:
        self.turns.append(Turn(text, risk, types))


@dataclass
class ScanContext:
    source: Source
    trust: Trust
    config: dict[str, Any]
    filename: str | None = None
    session: Session | None = None
    recursion: int = 0
    warnings: list[str] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)

    def log(self, msg: str) -> None:
        self.trace.append(msg)


__all__ = ["ScanContext", "Session", "Turn", "AttackType"]
