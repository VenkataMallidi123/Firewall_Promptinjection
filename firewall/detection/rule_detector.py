"""Weighted pattern rules, loaded from firewall/detection/rules/*.yaml.

Each YAML file declares one attack_type and a list of rules:

    - id: IO-001
      weight: 0.9                 # confidence if this pattern matches (0..1)
      description: ...
      pattern: '\\bignore\\b...'
      multiline: false            # optional: ^/$ match at line breaks
      case_sensitive: false       # optional: match original text instead of lower-cased view
      only_untrusted: false       # optional: only fire on retrieved/third-party content

Patterns run against several same-length "views" of the text (lower-cased,
homoglyph-folded, leet-folded) so obfuscated spellings still match.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..core.context import ScanContext
from ..core.models import AttackType, Finding, Segment, Trust
from ..normalization.unicode import match_views
from .base import Detector, snippet

__all__ = ["RuleDetector"]

RULES_DIR = Path(__file__).with_name("rules")

# Text just before a match that suggests the attack is being *discussed*, not issued.
MENTION_PREFIX = re.compile(
    r"(\be\.g\.?|\bfor example|\bsuch as|\blike|\bphrases?|\bcalled|\bknown as|\bexample|\bthe string"
    r"|\bquoted?|\bi\.e\.?|\bsays?|\bsaying|\bwords?)\s*[:,\-]?\s*[\"'“‘`]?\s*$",
    re.I,
)
QUOTES = "\"'`“”‘’"
# "never share your password" is advice, not an attack.
NEGATION_PREFIX = re.compile(r"\b(never|not|don'?t|do not|won'?t|will not|shouldn'?t|should not|must not|cannot|can'?t)\s+(\w+\s+)?$", re.I)


@dataclass
class Rule:
    id: str
    attack_type: AttackType
    pattern: re.Pattern
    weight: float
    description: str
    case_sensitive: bool = False
    only_untrusted: bool = False


def load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        attack = AttackType(doc["attack_type"])
        for r in doc["rules"]:
            flags = re.S
            if r.get("multiline"):
                flags |= re.M
            if not r.get("case_sensitive"):
                flags |= re.I
            try:
                pattern = re.compile(r["pattern"], flags)
            except re.error as exc:
                raise ValueError(f"{path.name} {r['id']}: bad regex: {exc}") from exc
            rules.append(Rule(r["id"], attack, pattern, float(r["weight"]), r.get("description", ""),
                              bool(r.get("case_sensitive")), bool(r.get("only_untrusted"))))
    return rules


def is_mention(text: str, start: int, end: int) -> bool:
    """Heuristic: is this match quoted or introduced as an example?"""
    if MENTION_PREFIX.search(text[max(0, start - 40):start]):
        return True
    before = text[max(0, start - 2):start]
    after = text[end:end + 40]
    return any(q in before for q in QUOTES) and any(q in after for q in QUOTES) and len(text) > (end - start) + 20


class RuleDetector(Detector):
    name = "rules"

    def __init__(self, config, rules_dir: Path = RULES_DIR):
        super().__init__(config)
        self.rules = load_rules(rules_dir)
        self.dampening = config["rules"]["mention_dampening"]

    def match_text(self, text: str, trust: Trust) -> list[tuple[Rule, int, int, bool]]:
        """All (rule, start, end, obfuscated) matches in `text`, de-duplicated across views.
        `obfuscated` is True when the match only appears after homoglyph/leet folding."""
        views = match_views(text)
        seen: set[tuple[str, int]] = set()
        hits: list[tuple[Rule, int, int, bool]] = []
        for rule in self.rules:
            if rule.only_untrusted and trust is not Trust.UNTRUSTED:
                continue
            for v, view in enumerate([text] if rule.case_sensitive else views):
                for m in rule.pattern.finditer(view):
                    if m.end() == m.start() or (rule.id, m.start()) in seen:
                        continue
                    seen.add((rule.id, m.start()))
                    hits.append((rule, m.start(), m.end(), v > 0))
        return hits

    def detect(self, segments: list[Segment], ctx: ScanContext, prior: list[Finding]) -> list[Finding]:
        findings: list[Finding] = []
        for i, seg in self.scannable(segments):
            for rule, start, end, obfuscated in self.match_text(seg.text, ctx.trust):
                score = rule.weight
                note = rule.description
                if NEGATION_PREFIX.search(seg.text[max(0, start - 25):start]):
                    score *= 0.3
                    note += " (negated - dampened)"
                elif is_mention(seg.text, start, end):
                    score *= self.dampening
                    note += " (looks quoted/discussed - dampened)"
                if obfuscated:
                    note += " (matched after homoglyph/leetspeak folding)"
                findings.append(Finding(
                    attack_type=rule.attack_type, detector=self.name, rule_id=rule.id, score=round(score, 3),
                    segment=i, start=start, end=end, evidence=snippet(seg.text, start, end), description=note,
                    obfuscated=obfuscated,
                ))
        return findings
