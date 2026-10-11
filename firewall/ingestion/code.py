"""Source code: natural-language injections live in comments, docstrings and string
literals. Those are scanned as child segments; the full file is emitted with any
malicious comment/string redacted in place."""
from __future__ import annotations

import re

from ..core.context import ScanContext
from ..core.models import Channel, Segment, Source
from .base import as_text

__all__ = ["extract_code"]

# Code comments are read by every developer, so they count as VISIBLE (unlike HTML comments).
PATTERNS: list[tuple[re.Pattern, Channel, str]] = [
    (re.compile(r'"""(.*?)"""|\'\'\'(.*?)\'\'\'', re.S), Channel.VISIBLE, "docstring"),
    (re.compile(r"/\*(.*?)\*/", re.S), Channel.VISIBLE, "block-comment"),
    (re.compile(r"(?:^|[ \t])(?:#|//|--)(?![#!/]|\s*[0-9a-fA-F]{3,6}\b)[ \t]?(.*)$", re.M), Channel.VISIBLE, "line-comment"),
    (re.compile(r'"((?:[^"\\\n]|\\.){6,})"|\'((?:[^\'\\\n]|\\.){6,})\'|`([^`]{6,})`'), Channel.VISIBLE, "string"),
]


def extract_code(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    code = as_text(data)
    root = Segment(text=code, channel=Channel.VISIBLE, location="code", scan=False)
    children: list[Segment] = []
    taken: list[tuple[int, int]] = []
    for pattern, channel, kind in PATTERNS:
        for m in pattern.finditer(code):
            if any(a <= m.start() < b for a, b in taken):
                continue  # already inside a docstring / block comment
            text = next((g for g in m.groups() if g is not None), "")
            if len(text.strip()) < 4:
                continue
            taken.append((m.start(), m.end()))
            line = code.count("\n", 0, m.start()) + 1
            children.append(Segment(text=text.strip(), channel=channel, location=f"code:{kind}:line{line}",
                                    parent=0, parent_span=(m.start(), m.end()), emit=False))
    return [root] + children
