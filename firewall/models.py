"""Core data types shared by every stage of the firewall.

    raw input ──ingest──► [Segment] ──detect──► [Finding] ──policy──► ScanResult

A *Segment* is a piece of text plus where it came from (its provenance).
A *Finding* is one piece of evidence that a segment contains an attack.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class AttackType(str, Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_CHANGE = "role_change"
    SECRET_EXTRACTION = "secret_extraction"
    TOOL_ABUSE = "tool_abuse"
    CREDENTIAL_THEFT = "credential_theft"
    CONTEXT_POISONING = "context_poisoning"
    MULTI_STEP_JAILBREAK = "multi_step_jailbreak"
    ENCODED_INSTRUCTIONS = "encoded_instructions"
    INDIRECT_INJECTION = "indirect_injection"


class Source(str, Enum):
    """What kind of content is being scanned (selects the extractor)."""
    TEXT = "text"
    USER = "user"            # chat message typed by the user
    HTML = "html"            # web pages
    MARKDOWN = "markdown"
    PDF = "pdf"
    DOCX = "docx"
    EMAIL = "email"          # RFC-822 .eml
    API_JSON = "api_json"    # API / tool responses
    CODE = "code"
    IMAGE = "image"          # PNG/JPEG -> OCR + metadata
    OCR_TEXT = "ocr_text"    # text already produced by an OCR engine


class Trust(str, Enum):
    """Who authored the content. Drives how suspicious we are."""
    TRUSTED = "trusted"      # operator / system content
    USER = "user"            # the human talking to the agent (direct injection)
    UNTRUSTED = "untrusted"  # retrieved / third-party data (indirect injection)


class Channel(str, Enum):
    """How the text was carried inside the original content."""
    VISIBLE = "visible"      # what a human reader would see
    HIDDEN = "hidden"        # present but invisible (display:none, white text, hidden Word runs...)
    COMMENT = "comment"      # HTML/code/PDF/Word comments
    METADATA = "metadata"    # document properties, email headers, EXIF
    ATTRIBUTE = "attribute"  # alt / title / aria-label / data-* attributes
    OCR = "ocr"              # text read out of an image
    DECODED = "decoded"      # produced by decoding another segment (base64, rot13, ...)


class Verdict(str, Enum):
    ALLOW = "allow"          # pass through unchanged
    SANITIZE = "sanitize"    # pass through with malicious spans removed
    BLOCK = "block"          # do not let the content reach the model


class Segment(BaseModel):
    text: str
    channel: Channel = Channel.VISIBLE
    location: str = ""                          # e.g. "pdf:page2", "json:$.items[0].desc"
    scan: bool = True                           # run detectors on this segment?
    emit: bool = True                           # include in sanitized output? (root segments only)
    depth: int = 0                              # decoding depth (0 = original content)
    parent: int | None = None                   # index of the segment this one was derived from
    parent_span: tuple[int, int] | None = None  # where in the parent it came from
    decoded_from: str | None = None             # "base64", "rot13", ...
    flags: dict[str, int] = Field(default_factory=dict)  # obfuscation signals found while normalizing


class Finding(BaseModel):
    attack_type: AttackType
    detector: str
    rule_id: str
    score: float                 # raw detector confidence 0..1
    weighted_score: float = 0.0  # after trust/channel weighting (set by policy)
    segment: int                 # index into ScanResult.segments
    start: int                   # span within that segment's text
    end: int
    evidence: str
    description: str = ""
    obfuscated: bool = False     # matched only after homoglyph/leetspeak folding


class ScanResult(BaseModel):
    verdict: Verdict
    risk_score: float
    attack_scores: dict[str, float]
    findings: list[Finding]
    segments: list[Segment]
    sanitized_text: str
    safe_text: str               # what an agent should actually feed its model
    source: Source
    trust: Trust
    warnings: list[str] = Field(default_factory=list)
    trace: list[str] = Field(default_factory=list)
    elapsed_ms: float = 0.0

    def detected_types(self, min_score: float = 0.3) -> list[str]:
        return [t for t, s in sorted(self.attack_scores.items(), key=lambda kv: -kv[1]) if s >= min_score]

    def summary(self) -> str:
        types = ", ".join(self.detected_types()) or "none"
        return f"{self.verdict.value.upper()} risk={self.risk_score:.2f} types=[{types}] source={self.source.value}"
