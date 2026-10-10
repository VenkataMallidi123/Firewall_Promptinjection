"""Markdown: visible text plus the places Markdown can hide text from a rendered view
(HTML comments, `[//]: # (...)` comments, image alt text, link titles, inline hidden HTML)."""
from __future__ import annotations

import re

from ..core.context import ScanContext
from ..core.models import Channel, Segment, Source
from .base import as_text, register
from .html import extract_html_segments

HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
MD_COMMENT = re.compile(r"^\[(?://|comment|_)\]:\s*(?:#|<>)\s*[(\"'](.*)[)\"']\s*$", re.M | re.I)
IMAGE_ALT = re.compile(r"!\[([^\]]{3,})\]\(")
LINK_TITLE = re.compile(r"\]\([^)\s]+\s+\"([^\"]{3,})\"\)")
INLINE_HTML = re.compile(r"<[a-zA-Z][^>]*>")


@register(Source.MARKDOWN)
def extract_markdown(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    text = as_text(data)
    hidden: list[Segment] = []
    for m in HTML_COMMENT.finditer(text):
        hidden.append(Segment(text=m.group(1).strip(), channel=Channel.COMMENT, location="markdown:html-comment", emit=False))
    for m in MD_COMMENT.finditer(text):
        hidden.append(Segment(text=m.group(1).strip(), channel=Channel.COMMENT, location="markdown:link-comment", emit=False))
    for m in IMAGE_ALT.finditer(text):
        hidden.append(Segment(text=m.group(1).strip(), channel=Channel.ATTRIBUTE, location="markdown:image-alt", emit=False))
    for m in LINK_TITLE.finditer(text):
        hidden.append(Segment(text=m.group(1).strip(), channel=Channel.ATTRIBUTE, location="markdown:link-title", emit=False))

    visible = MD_COMMENT.sub("", HTML_COMMENT.sub("", text))
    if INLINE_HTML.search(visible):
        # Raw HTML inside Markdown can carry display:none etc. Keep only the non-visible parts.
        for seg in extract_html_segments(visible, location="markdown:inline-html"):
            if seg.channel is not Channel.VISIBLE:
                hidden.append(seg)
                visible = visible.replace(seg.text, "")
    return [Segment(text=visible.strip(), channel=Channel.VISIBLE, location="markdown")] + hidden
