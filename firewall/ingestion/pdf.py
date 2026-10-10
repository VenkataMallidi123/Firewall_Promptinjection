"""PDF: page text, invisible text (white fill / render mode 3 / ~0pt font),
annotations (comments) and document metadata."""
from __future__ import annotations

import io

from pypdf import PdfReader

from ..core.context import ScanContext
from ..core.models import Channel, Segment, Source
from .base import as_bytes, register


def _hidden_text(page) -> list[str]:
    """Walk the content stream tracking fill colour / render mode / font size and
    collect text a reader would not see. Best-effort: some PDFs use other tricks
    (text under images, clipping) that this template does not cover."""
    state = {"white": False, "invisible": False}
    stack: list[dict] = []
    hidden: list[str] = []

    def before(op, args, cm, tm):
        if op == b"q":
            stack.append(dict(state))
        elif op == b"Q" and stack:
            state.update(stack.pop())
        elif op in (b"rg", b"g", b"k", b"sc", b"scn"):
            vals = [float(a) for a in args if isinstance(a, (int, float))]
            if op == b"k":  # CMYK white is 0 0 0 0
                state["white"] = bool(vals) and all(v <= 0.02 for v in vals)
            else:
                state["white"] = bool(vals) and all(v >= 0.98 for v in vals)
        elif op == b"Tr" and args:
            state["invisible"] = int(args[0]) == 3

    def on_text(text, cm, tm, font_dict, font_size):
        if not text.strip():
            return
        effective = abs(font_size * (tm[0] if tm else 1) * (cm[0] if cm else 1))
        if state["white"] or state["invisible"] or (0 < effective < 1.0):
            hidden.append(text)

    page.extract_text(visitor_operand_before=before, visitor_text=on_text)
    return hidden


@register(Source.PDF)
def extract_pdf(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    reader = PdfReader(io.BytesIO(as_bytes(data)))
    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception:
            ctx.warnings.append("encrypted PDF could not be opened")
            return []
    segments: list[Segment] = []
    extra: list[Segment] = []
    for i, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        try:
            for chunk in _hidden_text(page):
                chunk = chunk.strip()
                if len(chunk) >= 3:
                    extra.append(Segment(text=chunk, channel=Channel.HIDDEN, location=f"pdf:page{i} (invisible text)", emit=False))
                    text = text.replace(chunk, "")
        except Exception as exc:
            ctx.warnings.append(f"pdf hidden-text analysis failed on page {i}: {exc}")
        segments.append(Segment(text=text.strip(), channel=Channel.VISIBLE, location=f"pdf:page{i}"))
        for annot in page.get("/Annots") or []:
            try:
                obj = annot.get_object()
                contents = obj.get("/Contents")
                if contents and str(contents).strip():
                    extra.append(Segment(text=str(contents), channel=Channel.COMMENT, location=f"pdf:page{i}:annotation", emit=False))
            except Exception:
                continue
    for key, value in (reader.metadata or {}).items():
        if value and len(str(value).strip()) >= 3:
            extra.append(Segment(text=str(value), channel=Channel.METADATA, location=f"pdf:metadata{key}", emit=False))
    return segments + extra
