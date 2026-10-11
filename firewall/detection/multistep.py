"""7. Multi-Step Jailbreaks across turns (needs a Session).

Three cross-turn signals:
  * payload splitting - an attack phrase that only exists when consecutive turns are
    joined ("Ignore all previous" + "instructions and ...")
  * escalation        - an earlier turn set up a role-play / hypothetical frame and the
    current turn now carries an attack signal
  * persistence       - repeated suspicious turns (an attacker probing the guardrails)
"""
from __future__ import annotations

from ..core.context import ScanContext
from ..core.models import AttackType, Finding, Segment
from .base import Detector, snippet
from .rule_detector import RuleDetector

__all__ = ["MultiStepDetector"]

FRAMING_TYPES = {AttackType.ROLE_CHANGE.value, AttackType.MULTI_STEP_JAILBREAK.value}


class MultiStepDetector(Detector):
    name = "multistep"

    def __init__(self, config, rules: RuleDetector):
        super().__init__(config)
        self.rules = rules
        self.window = config["session"]["window"]

    def detect(self, segments: list[Segment], ctx: ScanContext, prior: list[Finding]) -> list[Finding]:
        if ctx.session is None or not ctx.session.turns:
            return []
        roots = [(i, s) for i, s in self.scannable(segments) if s.parent is None]
        if not roots:
            return []
        idx, current = roots[0]
        history = ctx.session.recent(self.window)
        findings: list[Finding] = []

        # 1) payload splitting: matches that straddle the boundary into the current turn
        previous = " ".join(t.text for t in history)
        joined = previous + " " + current.text
        boundary = len(previous) + 1
        for rule, start, end, _ in self.rules.match_text(joined, ctx.trust):
            if start < boundary < end:
                end_in_current = end - boundary
                findings.append(Finding(
                    attack_type=AttackType.MULTI_STEP_JAILBREAK, detector=self.name, rule_id="MS-SPLIT",
                    score=max(0.8, rule.weight), segment=idx, start=0, end=end_in_current,
                    evidence=snippet(joined, start, end, pad=10),
                    description=f"payload split across turns completes rule {rule.id}",
                ))
                break

        current_max = max((f.score for f in prior), default=0.0)

        # 2) escalation after a framing turn
        framed = any(t.types.get(k, 0) >= 0.3 for t in history for k in FRAMING_TYPES)
        if framed and current_max >= 0.3:
            findings.append(Finding(
                attack_type=AttackType.MULTI_STEP_JAILBREAK, detector=self.name, rule_id="MS-ESCALATE",
                score=round(min(0.95, 0.35 + 0.6 * current_max), 3), segment=idx, start=0, end=len(current.text),
                evidence=snippet(current.text, 0, min(len(current.text), 60)),
                description="attack signal after an earlier role-play / hypothetical framing turn",
            ))

        # 3) persistent probing
        suspicious_turns = sum(1 for t in history if t.risk >= 0.3)
        if suspicious_turns >= 2 and current_max >= 0.3:
            findings.append(Finding(
                attack_type=AttackType.MULTI_STEP_JAILBREAK, detector=self.name, rule_id="MS-PERSIST",
                score=0.6, segment=idx, start=0, end=len(current.text),
                evidence=f"{suspicious_turns} of the last {len(history)} turns were suspicious",
                description="repeated attempts across the conversation",
            ))
        return findings
