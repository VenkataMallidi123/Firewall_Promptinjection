"""Stage 1 routing table: which extractor handles which input format.

To support a new format: write `extract_x(data, ctx) -> list[Segment]` in its own module
and add one line to EXTRACTORS below. Unknown formats fall back to plain text.
"""
from __future__ import annotations

from ..core.context import ScanContext
from ..core.models import Segment, Source
from .api_json import extract_json
from .base import Extractor
from .code import extract_code
from .docx import extract_docx
from .email import extract_email
from .html import extract_html
from .image_ocr import extract_image
from .markdown import extract_markdown
from .pdf import extract_pdf
from .text import extract_ocr_text, extract_text

__all__ = ["extract", "get_extractor"]

EXTRACTORS: dict[Source, Extractor] = {
    Source.USER:     extract_text,       # chat messages
    Source.TEXT:     extract_text,
    Source.OCR_TEXT: extract_ocr_text,
    Source.HTML:     extract_html,       # web pages
    Source.MARKDOWN: extract_markdown,
    Source.PDF:      extract_pdf,
    Source.DOCX:     extract_docx,       # Word documents
    Source.EMAIL:    extract_email,      # .eml, including attachments
    Source.API_JSON: extract_json,       # API / tool responses
    Source.CODE:     extract_code,
    Source.IMAGE:    extract_image,      # metadata (+ OCR when Tesseract is installed)
}


def get_extractor(source: Source) -> Extractor:
    return EXTRACTORS.get(source, extract_text)


def extract(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    """Stage 1 entry point: run the extractor for ctx.source."""
    return get_extractor(ctx.source)(data, ctx)
