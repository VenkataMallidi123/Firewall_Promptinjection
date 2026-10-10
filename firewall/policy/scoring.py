"""Stage 4 - POLICY: turn many pieces of evidence into one decision.

1. weight each finding:   weighted = score x trust_weight[source trust] x channel_weight[segment channel]
2. per attack type:       take the best finding per rule, combine rules with noisy-OR
                          (independent pieces of evidence reinforce each other)
3. overall risk:          noisy-OR of the attack types that clear `combine_min`
                          (weak, isolated signals don't add up to a false positive)
4. verdict:               ALLOW < sanitize threshold <= SANITIZE < block threshold <= BLOCK
"""
from __future__ import annotations

from collections import defaultdict

from ..context import ScanContext
from ..models import Finding, Segment, Verdict


def noisy_or(scores) -> float:
    p = 1.0
    for s in scores:
        p *= 1.0 - s
    return 1.0 - p


def score_findings(findings: list[Finding], segments: list[Segment], ctx: ScanContext) -> tuple[Verdict, float, dict[str, float]]:
    cfg = ctx.config
    trust_w = cfg["trust_weights"][ctx.trust.value]
    for f in findings:
        channel_w = cfg["channel_weights"][segments[f.segment].channel.value]
        f.weighted_score = round(min(1.0, f.score * trust_w * channel_w), 3)

    per_rule: dict[str, dict[str, float]] = defaultdict(dict)
    for f in findings:
        rules = per_rule[f.attack_type.value]
        rules[f.rule_id] = max(rules.get(f.rule_id, 0.0), f.weighted_score)
    type_scores = {t: round(noisy_or(r.values()), 3) for t, r in per_rule.items()}

    th = cfg["thresholds"]
    strong = [s for s in type_scores.values() if s >= th["combine_min"]]
    risk = noisy_or(strong) if strong else max(type_scores.values(), default=0.0)
    risk = round(risk, 3)

    if risk >= th["block"]:
        verdict = Verdict.BLOCK
    elif risk >= th["sanitize"]:
        verdict = Verdict.SANITIZE
    else:
        verdict = Verdict.ALLOW
    return verdict, risk, type_scores
