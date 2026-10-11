"""API / tool responses (JSON). Every string value becomes its own segment, tagged with
its JSON path, so a malicious `description` field is located precisely.
The full JSON is emitted (with redactions applied) as the sanitized output."""
from __future__ import annotations

import json

from ..core.context import ScanContext
from ..core.models import Channel, Segment, Source
from .base import as_text
from .text import extract_text

__all__ = ["extract_json"]


def extract_json(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    raw = as_text(data)
    try:
        obj = json.loads(raw)
    except ValueError:
        ctx.warnings.append("invalid JSON, scanned as plain text")
        return extract_text(raw, ctx)

    pretty = json.dumps(obj, indent=2, ensure_ascii=False)
    root = Segment(text=pretty, channel=Channel.VISIBLE, location="json", scan=False)
    children: list[Segment] = []
    cursor = 0

    def walk(node, path: str) -> None:
        nonlocal cursor
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str) and len(node.strip()) >= 2:
            encoded = json.dumps(node, ensure_ascii=False)
            pos = pretty.find(encoded, cursor)
            span = (pos, pos + len(encoded)) if pos >= 0 else None
            if pos >= 0:
                cursor = pos + len(encoded)
            children.append(Segment(text=node, channel=Channel.VISIBLE, location=f"json:{path}",
                                    parent=0, parent_span=span, emit=False))

    walk(obj, "$")
    return [root] + children
