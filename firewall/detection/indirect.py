"""9. Indirect Prompt Injection - instructions arriving through *data* (web pages, emails,
documents, API responses) rather than from the user.

Only runs on UNTRUSTED content. Signals:
  * text that addresses the AI reading it ("Note to the AI assistant: ...")
  * any strong attack finding inside retrieved data is, by definition, an indirect
    injection - boosted further when it sits in a channel humans cannot see
"""
from __future__ import annotations

import re

from ..core.context import ScanContext
from ..core.models import AttackType, Channel, Finding, Segment, Trust
from ..normalization.unicode import match_views
from .base import Detector, snippet

__all__ = ["IndirectDetector"]

AI = r"(ai|a\.i\.|llm|assistant|chatbot|language model|agent|copilot|gpt|chatgpt|claude|gemini|bot|model)s?"
ADDRESSED_TO_AI = [
    re.compile(r"\b(note|message|instructions?|attention|notice|memo|reminder)\s+(to|for)\s+(the\s+|any\s+|all\s+)?" + AI + r"\b", re.I),
    re.compile(r"\b(if|when)\s+you\s+are\s+(an?\s+)?" + AI + r"\b", re.I),
    re.compile(r"\b(dear|hey|hello|hi|attention)\s+" + AI + r"\b", re.I),
    re.compile(r"\b" + AI + r"\s+(reading|processing|summari[sz]ing|parsing|analy[sz]ing)\s+(this|the)\b", re.I),
    re.compile(r"\bwhen\s+(summari[sz]ing|processing|reading|you read|you process|you summari[sz]e|parsing)\s+(this|the)\s+"
               r"(email|page|document|message|file|content|text|website|article|data|response)\b", re.I),
    re.compile(r"\b(as an?|any)\s+" + AI + r"\s+(reading|processing|that reads|that processes|you must|must)\b", re.I),
]
HIDDEN_CHANNELS = {Channel.HIDDEN, Channel.COMMENT, Channel.METADATA, Channel.ATTRIBUTE}


class IndirectDetector(Detector):
    name = "indirect"

    def detect(self, segments: list[Segment], ctx: ScanContext, prior: list[Finding]) -> list[Finding]:
        if ctx.trust is not Trust.UNTRUSTED:
            return []
        findings: list[Finding] = []

        for i, seg in self.scannable(segments):
            for view in match_views(seg.text)[:2]:
                hit = next((m for p in ADDRESSED_TO_AI for m in p.finditer(view)), None)
                if hit:
                    findings.append(Finding(
                        attack_type=AttackType.INDIRECT_INJECTION, detector=self.name, rule_id="IND-ADDR",
                        score=0.65, segment=i, start=hit.start(), end=hit.end(),
                        evidence=snippet(seg.text, hit.start(), hit.end()),
                        description="retrieved content addresses the AI directly",
                    ))
                    break

        best: dict[int, Finding] = {}
        for f in prior:
            # Only mirror explainable evidence; the ML score alone is too weak to double-count.
            if f.score < 0.5 or f.attack_type is AttackType.INDIRECT_INJECTION or f.detector == "ml":
                continue
            seg = segments[f.segment]
            root = seg
            while root.parent is not None:
                root = segments[root.parent]
            hidden = seg.channel in HIDDEN_CHANNELS or root.channel in HIDDEN_CHANNELS
            score = min(1.0, f.score * (1.1 if hidden else 0.95))
            if f.segment not in best or best[f.segment].score < score:
                where = f"{seg.channel.value} channel at {seg.location}"
                best[f.segment] = Finding(
                    attack_type=AttackType.INDIRECT_INJECTION, detector=self.name, rule_id="IND-DATA",
                    score=round(score, 3), segment=f.segment, start=f.start, end=f.end, evidence=f.evidence,
                    description=f"{f.attack_type.value} embedded in retrieved data ({where})",
                )
        findings.extend(best.values())
        return findings
