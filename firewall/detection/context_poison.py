"""6. Context Poisoning - structural check that regexes alone express poorly:
a forged conversation transcript ("User: ... / Assistant: ...") embedded in content
so the model believes earlier turns (e.g. an assistant agreeing to misbehave) happened."""
from __future__ import annotations

import re

from ..core.context import ScanContext
from ..core.models import AttackType, Finding, Segment, Trust
from .base import Detector, snippet

__all__ = ["ContextPoisonDetector"]

ROLE_LINE = re.compile(
    r"(?im)^\s*(?:\*\*|#+\s*|>\s*)?(user|human|assistant|ai|system|bot|chatbot|gpt|chatgpt|claude|model)\s*(?:\*\*)?\s*:"
)
MODEL_ROLES = {"assistant", "ai", "bot", "chatbot", "gpt", "chatgpt", "claude", "model", "system"}


class ContextPoisonDetector(Detector):
    name = "context_poison"

    def detect(self, segments: list[Segment], ctx: ScanContext, prior: list[Finding]) -> list[Finding]:
        findings: list[Finding] = []
        for i, seg in self.scannable(segments):
            matches = list(ROLE_LINE.finditer(seg.text))
            roles = {m.group(1).lower() for m in matches}
            if len(matches) >= 2 and len(roles) >= 2 and roles & MODEL_ROLES:
                # A pasted transcript from the user is often legitimate ("summarise this chat");
                # the same structure inside retrieved data is far more suspicious.
                score = 0.75 if ctx.trust is Trust.UNTRUSTED else 0.50
                start, end = matches[0].start(), matches[-1].end()
                findings.append(Finding(
                    attack_type=AttackType.CONTEXT_POISONING, detector=self.name, rule_id="CP-DIALOG",
                    score=score, segment=i, start=start, end=end, evidence=snippet(seg.text, start, end),
                    description=f"forged conversation turns ({', '.join(sorted(roles))})",
                ))
        return findings
