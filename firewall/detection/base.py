"""Stage 3 - DETECT.

Every detector gets all segments plus the findings of the detectors that ran
before it (so later detectors can build on earlier evidence), and returns new
Findings. Detectors never decide the verdict - that is the policy stage's job.

To add a detector: subclass Detector, implement detect(), and add it in
Firewall._build_detection_chain() (firewall/pipeline.py).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..core.context import ScanContext
from ..core.models import Finding, Segment

__all__ = ["Detector", "snippet"]


class Detector(ABC):
    name: str = "detector"

    def __init__(self, config: dict[str, Any]):
        self.config = config

    @abstractmethod
    def detect(self, segments: list[Segment], ctx: ScanContext, prior: list[Finding]) -> list[Finding]:
        ...

    @staticmethod
    def scannable(segments: list[Segment]):
        for i, seg in enumerate(segments):
            if seg.scan and seg.text:
                yield i, seg


def snippet(text: str, start: int, end: int, pad: int = 25) -> str:
    left = max(0, start - pad)
    right = min(len(text), end + pad)
    s = text[left:right].replace("\n", " ")
    return ("..." if left else "") + s + ("..." if right < len(text) else "")
