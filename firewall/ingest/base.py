"""Stage 1 - INGEST.

An *extractor* turns raw content (bytes or str) into a list of Segments, each tagged
with the channel it was carried in (visible text, hidden text, comment, metadata...).
Surfacing *non-visible* channels is what makes indirect injection detectable: the
attacker hides instructions where a human reviewer will not look.

To support a new input type: write `def extract_x(data, ctx) -> list[Segment]`,
decorate it with `@register(Source.X)`, and import the module in ingest/__init__.py.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from ..context import ScanContext
from ..models import Segment, Source

Extractor = Callable[[bytes | str, ScanContext], list[Segment]]
_REGISTRY: dict[Source, Extractor] = {}


def register(*sources: Source):
    def deco(fn: Extractor) -> Extractor:
        for s in sources:
            _REGISTRY[s] = fn
        return fn
    return deco


EXTENSIONS: dict[str, Source] = {
    ".txt": Source.TEXT, ".log": Source.TEXT, ".csv": Source.TEXT,
    ".md": Source.MARKDOWN, ".markdown": Source.MARKDOWN,
    ".html": Source.HTML, ".htm": Source.HTML, ".xhtml": Source.HTML,
    ".pdf": Source.PDF,
    ".docx": Source.DOCX,
    ".eml": Source.EMAIL,
    ".json": Source.API_JSON,
    ".png": Source.IMAGE, ".jpg": Source.IMAGE, ".jpeg": Source.IMAGE,
    ".gif": Source.IMAGE, ".bmp": Source.IMAGE, ".tif": Source.IMAGE, ".tiff": Source.IMAGE, ".webp": Source.IMAGE,
    **{ext: Source.CODE for ext in (".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".cs", ".go", ".rb",
                                     ".php", ".rs", ".sh", ".ps1", ".sql", ".yaml", ".yml", ".kt", ".swift")},
}


def as_text(data: bytes | str) -> str:
    if isinstance(data, str):
        return data
    for enc in ("utf-8-sig", "utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else ("utf-8-sig",):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1")


def as_bytes(data: bytes | str) -> bytes:
    return data.encode("utf-8") if isinstance(data, str) else data


def detect_source(data: bytes | str, filename: str | None = None) -> Source:
    """Pick a Source from the file extension, falling back to content sniffing."""
    if filename:
        ext = Path(filename).suffix.lower()
        if ext in EXTENSIONS:
            return EXTENSIONS[ext]
    if isinstance(data, bytes):
        head = data[:8]
        if head.startswith(b"%PDF"):
            return Source.PDF
        if head.startswith(b"PK\x03\x04") and b"word/" in data[:4096]:
            return Source.DOCX
        if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM")) or data[8:12] == b"WEBP":
            return Source.IMAGE
    text = as_text(data)[:4096]
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            json.loads(as_text(data))
            return Source.API_JSON
        except ValueError:
            pass
    if re.search(r"<!doctype html|<html[\s>]|<body[\s>]|<div[\s>]", text, re.I):
        return Source.HTML
    if re.search(r"^from:\s", text, re.I | re.M) and re.search(r"^subject:\s", text, re.I | re.M):
        return Source.EMAIL
    return Source.TEXT


def get_extractor(source: Source) -> Extractor:
    return _REGISTRY.get(source) or _REGISTRY[Source.TEXT]


def extract(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    return get_extractor(ctx.source)(data, ctx)


def extend_rebased(out: list[Segment], segs: list[Segment]) -> None:
    """Append segments produced by another extractor, fixing their parent indices."""
    offset = len(out)
    for s in segs:
        if s.parent is not None:
            s.parent += offset
        out.append(s)


def extract_nested(data: bytes | str, filename: str | None, ctx: ScanContext, prefix: str) -> list[Segment]:
    """Extract an embedded object (e.g. an email attachment) with recursion limits."""
    limit = ctx.config["limits"]["max_recursion"]
    if ctx.recursion >= limit:
        ctx.warnings.append(f"recursion limit reached at {prefix}")
        return []
    source = detect_source(data, filename)
    ctx.recursion += 1
    saved = ctx.source
    try:
        ctx.source = source
        segs = get_extractor(source)(data, ctx)
    except Exception as exc:  # a broken attachment must not break the whole scan
        ctx.warnings.append(f"failed to extract {prefix}: {exc}")
        segs = []
    finally:
        ctx.source = saved
        ctx.recursion -= 1
    for s in segs:
        s.location = f"{prefix}/{s.location}" if s.location else prefix
    return segs
