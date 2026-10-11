"""Plain text, chat messages and pre-OCR'd text: the whole thing is one visible segment."""
from __future__ import annotations

from ..core.context import ScanContext
from ..core.models import Channel, Segment, Source
from .base import as_text

__all__ = ["extract_ocr_text", "extract_text"]


def extract_text(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    return [Segment(text=as_text(data), channel=Channel.VISIBLE, location=ctx.source.value)]


def extract_ocr_text(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    return [Segment(text=as_text(data), channel=Channel.OCR, location="ocr")]
