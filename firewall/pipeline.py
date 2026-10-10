"""The Firewall: orchestrates the five stages.

    fw = Firewall()
    result = fw.scan(email_bytes, source="email")      # trust defaults to UNTRUSTED for data
    result = fw.scan("hi, summarise my inbox", source="user", session=session)
    if result.verdict is Verdict.BLOCK: ...
    model_input = result.safe_text
"""
from __future__ import annotations

import time
from pathlib import Path

from .core.config import load_config
from .core.context import ScanContext, Session
from .detection import (ContextPoisonDetector, Detector, EncodingDetector, IndirectDetector, MLDetector,
                        MultiStepDetector, RuleDetector)
from .ingestion import detect_source, extract
from .ingestion.base import as_text
from .core.models import Channel, ScanResult, Segment, Source, Trust, Verdict
from .normalization import expand_decoded, normalize_segments
from .decision import score_findings
from .enforcement import neutralize


class Firewall:
    def __init__(self, config_path: str | Path | None = None, overrides: dict | None = None):
        self.config = load_config(config_path, overrides)
        self.rules = RuleDetector(self.config)
        self.detectors = self._build_detectors()

    def _build_detectors(self) -> list[Detector]:
        """Order matters: content detectors first, then the ones that reason over their findings."""
        on = self.config["detectors"]
        chain: list[tuple[str, Detector]] = [
            ("rules", self.rules),
            ("context_poison", ContextPoisonDetector(self.config)),
            ("multistep", MultiStepDetector(self.config, self.rules)),
            ("ml", MLDetector(self.config) if on.get("ml") else None),
            ("encoding", EncodingDetector(self.config)),
            ("indirect", IndirectDetector(self.config)),
        ]
        return [d for key, d in chain if d is not None and on.get(key, True)]

    def scan(self, content: bytes | str, source: Source | str | None = None, trust: Trust | str | None = None,
             filename: str | None = None, session: Session | None = None) -> ScanResult:
        t0 = time.perf_counter()
        src = Source(source) if source else detect_source(content, filename)
        tr = Trust(trust) if trust else (Trust.USER if src is Source.USER else Trust.UNTRUSTED)
        ctx = ScanContext(source=src, trust=tr, config=self.config, filename=filename, session=session)

        max_bytes = self.config["limits"]["max_input_bytes"]
        if len(content) > max_bytes:
            ctx.warnings.append(f"input truncated to {max_bytes} bytes")
            content = content[:max_bytes]

        # 1. INGEST
        try:
            segments = extract(content, ctx)
        except Exception as exc:
            # Fail safe: if a parser chokes, still scan whatever text we can recover.
            ctx.warnings.append(f"{src.value} extractor failed ({exc}); scanned as raw text")
            segments = [Segment(text=as_text(content), channel=Channel.VISIBLE, location="raw")]
        ctx.log(f"ingest: {len(segments)} segments from {src.value}")

        # 2. NORMALIZE + DECODE
        segments = normalize_segments(segments, ctx)
        segments = expand_decoded(segments, ctx)

        # 3. DETECT
        findings = []
        for det in self.detectors:
            new = det.detect(segments, ctx, findings)
            findings.extend(new)
            ctx.log(f"detector {det.name}: {len(new)} findings")

        # 4. POLICY
        verdict, risk, type_scores = score_findings(findings, segments, ctx)
        th = self.config["thresholds"]["combine_min"]
        types = [t for t, s in sorted(type_scores.items(), key=lambda kv: -kv[1]) if s >= th]
        ctx.log(f"policy: risk={risk} verdict={verdict.value}")

        # 5. NEUTRALIZE
        sanitized, safe = neutralize(segments, findings, verdict, ctx, types)

        if session is not None:
            turn_text = " ".join(s.text for s in segments if s.parent is None and s.scan and s.channel is Channel.VISIBLE)
            session.add(turn_text, risk, type_scores)

        findings.sort(key=lambda f: -f.weighted_score)
        return ScanResult(
            verdict=verdict, risk_score=risk, attack_scores=type_scores, findings=findings, segments=segments,
            sanitized_text=sanitized, safe_text=safe, source=src, trust=tr, warnings=ctx.warnings,
            trace=ctx.trace, elapsed_ms=round((time.perf_counter() - t0) * 1000, 2),
        )

    def scan_file(self, path: str | Path, trust: Trust | str | None = None, session: Session | None = None) -> ScanResult:
        p = Path(path)
        return self.scan(p.read_bytes(), filename=p.name, trust=trust, session=session)


__all__ = ["Firewall", "Session", "Verdict"]
