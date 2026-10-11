"""8. Encoded Instructions.

Runs after the content detectors. Two signals:
  * an attack was found inside a *decoded* segment -> the content smuggled an
    instruction through an encoding (base64, rot13, hex, unicode tags, ...)
  * obfuscation markers recorded during normalization (zero-width chars inside
    words, mixed-script homoglyph words, invisible tag characters)
"""
from __future__ import annotations

from ..core.context import ScanContext
from ..core.models import AttackType, Finding, Segment
from .base import Detector, snippet

__all__ = ["EncodingDetector"]


class EncodingDetector(Detector):
    name = "encoding"

    def detect(self, segments: list[Segment], ctx: ScanContext, prior: list[Finding]) -> list[Finding]:
        findings: list[Finding] = []
        best: dict[tuple[int, int, int], Finding] = {}

        for f in prior:
            seg = segments[f.segment]
            if seg.depth == 0 or seg.parent is None or f.attack_type is AttackType.ENCODED_INSTRUCTIONS:
                continue
            start, end = seg.parent_span or (0, len(segments[seg.parent].text))
            key = (seg.parent, start, end)
            score = max(0.75, f.score)
            if key not in best or best[key].score < score:
                parent_text = segments[seg.parent].text
                best[key] = Finding(
                    attack_type=AttackType.ENCODED_INSTRUCTIONS, detector=self.name, rule_id="EN-DECODED",
                    score=round(score, 3), segment=seg.parent, start=start, end=end,
                    evidence=f"{seg.decoded_from} -> {seg.text[:100]!r}",
                    description=f"{f.attack_type.value} hidden with {seg.decoded_from} encoding "
                                f"(original: {snippet(parent_text, start, min(end, start + 40), pad=0)})",
                )
        findings.extend(best.values())

        # Attack text that only matched after folding homoglyphs / leetspeak (1gn0r3, ignоre).
        for f in prior:
            if f.obfuscated and f.score >= 0.4:
                findings.append(Finding(
                    attack_type=AttackType.ENCODED_INSTRUCTIONS, detector=self.name, rule_id="EN-FOLDED",
                    score=round(max(0.7, f.score * 0.9), 3), segment=f.segment, start=f.start, end=f.end,
                    evidence=f.evidence, description=f"{f.attack_type.value} written with homoglyphs/leetspeak",
                ))
                break

        hit_segments = {f.segment for f in prior}
        for i, seg in enumerate(segments):
            fl = seg.flags
            if fl.get("tag_smuggling") and seg.depth == 0:
                findings.append(self._flag(i, seg, 0.85, "EN-TAGS", f"{fl['tag_smuggling']} invisible Unicode tag characters carry hidden text"))
            obfuscated = fl.get("invisible_in_words", 0) >= 2 or fl.get("mixed_script_words", 0) >= 1
            if obfuscated:
                score = 0.7 if i in hit_segments else 0.35
                findings.append(self._flag(i, seg, score, "EN-OBFUSC",
                                           f"obfuscated text (zero-width in words: {fl.get('invisible_in_words', 0)}, "
                                           f"mixed-script words: {fl.get('mixed_script_words', 0)})"))
        return findings

    def _flag(self, i: int, seg: Segment, score: float, rule_id: str, desc: str) -> Finding:
        return Finding(attack_type=AttackType.ENCODED_INSTRUCTIONS, detector=self.name, rule_id=rule_id, score=score,
                       segment=i, start=0, end=0, evidence=seg.text[:80], description=desc)
