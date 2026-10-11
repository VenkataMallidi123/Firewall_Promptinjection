"""The Firewall: the only place that calls the five stages, in order.

    fw = Firewall()
    result = fw.scan(email_bytes, source="email")      # trust defaults to UNTRUSTED for data
    result = fw.scan("hi, summarise my inbox", source="user", session=session)
    if result.verdict is Verdict.BLOCK: ...
    model_input = result.safe_text

Agents normally use FirewallGuard (firewall/guard.py) rather than calling scan() directly.
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

__all__ = ["Firewall"]


class Firewall:
    """The 5-stage inspection pipeline. One instance can be shared by many guards and requests."""

    def __init__(self, config_path: str | Path | None = None, overrides: dict | None = None):
        """Load the configuration and build the detection chain.

        config_path: optional YAML file merged over firewall/core/config.yaml.
        overrides:   optional dict merged on top, e.g. {"thresholds": {"block": 0.7}}.
        """
        self.config = load_config(config_path, overrides)
        self.rules = RuleDetector(self.config)
        self.detectors = self._build_detection_chain()

    def _build_detection_chain(self) -> list[Detector]:
        """Create the stage 3 detectors in the order they run, skipping any disabled in config.

        Order matters: content detectors first, then the ones that reason over their findings.
        """
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

    def _create_scan_context(self, content: bytes | str, source: Source | str | None, trust: Trust | str | None,
                             filename: str | None, session: Session | None) -> ScanContext:
        """Resolve the content type and trust level, and create the per-scan state shared by all stages."""
        src = Source(source) if source else detect_source(content, filename)
        tr = Trust(trust) if trust else (Trust.USER if src is Source.USER else Trust.UNTRUSTED)
        return ScanContext(source=src, trust=tr, config=self.config, filename=filename, session=session)

    def _run_ingestion(self, content: bytes | str, ctx: ScanContext) -> list[Segment]:
        """Run stage 1 with its safety limits (size cap, fail-safe on parser errors).

        This is the only place that calls into firewall.ingestion.
        """
        max_bytes = self.config["limits"]["max_input_bytes"]
        if len(content) > max_bytes:
            ctx.warnings.append(f"input truncated to {max_bytes} bytes")
            content = content[:max_bytes]
        try:
            segments = extract(content, ctx)
        except Exception as exc:
            # Fail safe: if a parser chokes, still scan whatever text we can recover.
            ctx.warnings.append(f"{ctx.source.value} extractor failed ({exc}); scanned as raw text")
            segments = [Segment(text=as_text(content), channel=Channel.VISIBLE, location="raw")]
        ctx.log(f"ingestion: {len(segments)} segments from {ctx.source.value}")
        return segments

    def read_unprotected(self, content: bytes | str, source: Source | str | None = None,
                         filename: str | None = None) -> list[Segment]:
        """Stage 1 only, with NO protection: every text layer, hidden ones included.

        This is what an ordinary document loader hands a model. The demo uses it for
        its "without firewall" run; real integrations should use FirewallGuard or scan() instead.
        """
        ctx = self._create_scan_context(content, source, Trust.UNTRUSTED, filename, None)
        return self._run_ingestion(content, ctx)

    def scan(self, content: bytes | str, source: Source | str | None = None, trust: Trust | str | None = None,
             filename: str | None = None, session: Session | None = None) -> ScanResult:
        """Run all five stages on one piece of content and return the full ScanResult.

        source:   content type (user, html, pdf, email...); detected from filename/content if omitted.
        trust:    who wrote it; defaults to USER for chat messages and UNTRUSTED for everything else.
        filename: helps detect the format of files and attachments.
        session:  conversation memory for multi-turn detection; this turn is added to it.
        """
        t0 = time.perf_counter()
        ctx = self._create_scan_context(content, source, trust, filename, session)
        src, tr = ctx.source, ctx.trust

        # Stage 1. INGESTION
        segments = self._run_ingestion(content, ctx)

        # Stage 2. NORMALIZATION
        segments = normalize_segments(segments, ctx)
        segments = expand_decoded(segments, ctx)

        # Stage 3. DETECTION
        findings = []
        for det in self.detectors:
            new = det.detect(segments, ctx, findings)
            findings.extend(new)
            ctx.log(f"detector {det.name}: {len(new)} findings")

        # Stage 4. DECISION
        verdict, risk, type_scores = score_findings(findings, segments, ctx)
        th = self.config["thresholds"]["combine_min"]
        types = [t for t, s in sorted(type_scores.items(), key=lambda kv: -kv[1]) if s >= th]
        ctx.log(f"decision: risk={risk} verdict={verdict.value}")

        # Stage 5. ENFORCEMENT
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
        """Read a file from disk and scan it; the file name is used to detect its format."""
        p = Path(path)
        return self.scan(p.read_bytes(), filename=p.name, trust=trust, session=session)
