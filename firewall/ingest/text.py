"""Plain text, chat messages and pre-OCR'd text: the whole thing is one visible segment."""
from __future__ import annotations

from ..context import ScanContext
from ..models import Channel, Segment, Source
from .base import as_text, register


@register(Source.TEXT, Source.USER)
def extract_text(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    return [Segment(text=as_text(data), channel=Channel.VISIBLE, location=ctx.source.value)]


@register(Source.OCR_TEXT)
def extract_ocr_text(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    return [Segment(text=as_text(data), channel=Channel.OCR, location="ocr")]
