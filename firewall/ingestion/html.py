"""HTML / web pages.

Separates what a human sees from what only a machine sees:
  * hidden text  - display:none, visibility:hidden, font-size:0, opacity:0, off-screen,
                   white-on-white, `hidden`/aria-hidden, .sr-only-style classes, <template>
  * comments     - <!-- ... -->
  * attributes   - alt, title, aria-label, placeholder, data-*
  * metadata     - <meta content>, JSON-LD
Only the visible text is emitted in the sanitized output.
"""
from __future__ import annotations

import re

from bs4 import BeautifulSoup, Comment, Declaration, Doctype, NavigableString, ProcessingInstruction, Tag

from ..core.context import ScanContext
from ..core.models import Channel, Segment, Source
from .base import as_text

__all__ = ["extract_html", "extract_html_segments"]

HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|font-size\s*:\s*[01](?:\.\d+)?(?:px|pt)?\s*(?:;|$|!)"
    r"|font-size\s*:\s*0(?:\.\d+)?(?:em|rem|%)"
    r"|opacity\s*:\s*0(?:\.0\d*)?\s*(?:;|$|!)"
    r"|(?:left|top|right|text-indent|margin-left)\s*:\s*-\d{3,}"
    r"|clip\s*:\s*rect\(\s*0"
    r"|(?:max-)?(?:height|width)\s*:\s*0(?:px)?\s*(?:;|$)",
    re.I,
)
WHITE = r"(?:#fff(?:fff)?\b|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255)"
WHITE_TEXT = re.compile(r"(?<![-\w])color\s*:\s*(?:" + WHITE + r"|transparent\b)", re.I)
BACKGROUND = re.compile(r"background(?:-color)?\s*:\s*([^;]+)", re.I)
HIDDEN_CLASSES = {"hidden", "sr-only", "visually-hidden", "d-none", "invisible", "screen-reader-text", "hide"}
INVISIBLE_TAGS = {"template", "noscript"}
SKIP_TAGS = {"style", "script", "head", "title"}
BLOCK_TAGS = {"p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6", "td", "th", "tr", "section", "article",
              "blockquote", "pre", "ul", "ol", "table", "body", "header", "footer", "main", "nav", "aside",
              "form", "br", "hr", "dd", "dt", "figcaption", "address"}
TEXT_ATTRS = ("alt", "title", "aria-label", "placeholder", "aria-description", "summary")


def hidden_reason(tag: Tag | None) -> str | None:
    """Why this element (or an ancestor) is invisible to a human, or None."""
    white_text = False
    has_bg = False
    node = tag
    while isinstance(node, Tag):
        if node.name in INVISIBLE_TAGS:
            return f"<{node.name}>"
        if node.has_attr("hidden") or node.get("aria-hidden") == "true":
            return "hidden attribute"
        if node.name == "input" and node.get("type") == "hidden":
            return "hidden input"
        classes = set(node.get("class") or [])
        if classes & HIDDEN_CLASSES:
            return f"class {sorted(classes & HIDDEN_CLASSES)[0]}"
        style = node.get("style") or ""
        if style:
            if m := HIDDEN_STYLE.search(style):
                return f"style {m.group(0).strip(' ;')}"
            if WHITE_TEXT.search(style):
                white_text = True
            if bg := BACKGROUND.search(style):
                if not re.search(WHITE, bg.group(1), re.I):
                    has_bg = True
        node = node.parent
    if white_text and not has_bg:
        return "white-on-white text"
    return None


def _block_parent(tag: Tag) -> int:
    node = tag
    while isinstance(node, Tag):
        if node.name in BLOCK_TAGS:
            return id(node)
        node = node.parent
    return 0


def extract_html_segments(html: str, location: str = "html") -> list[Segment]:
    soup = BeautifulSoup(html, "html.parser")
    segments: list[Segment] = []
    visible: list[str] = []
    last_block = None

    for node in soup.descendants:
        if isinstance(node, Comment):
            text = str(node).strip()
            if text:
                segments.append(Segment(text=text, channel=Channel.COMMENT, location=f"{location}:comment", emit=False))
            continue
        if isinstance(node, (Doctype, Declaration, ProcessingInstruction)):
            continue  # e.g. <!DOCTYPE html>: markup, not text
        if not isinstance(node, NavigableString):
            continue
        parent = node.parent
        text = str(node)
        if not text.strip():
            continue
        if parent is not None and parent.name == "script":
            if (parent.get("type") or "").lower() == "application/ld+json":
                segments.append(Segment(text=text.strip(), channel=Channel.METADATA, location=f"{location}:json-ld", emit=False))
            continue
        if parent is not None and parent.name in SKIP_TAGS - {"title"}:
            continue
        if reason := hidden_reason(parent):
            segments.append(Segment(text=text.strip(), channel=Channel.HIDDEN,
                                    location=f"{location}:<{parent.name}> ({reason})", emit=False))
            continue
        block = _block_parent(parent)
        sep = " " if block == last_block else "\n"
        visible.append((sep if visible else "") + text.strip())
        last_block = block

    for tag in soup.find_all(True):
        for attr in TEXT_ATTRS:
            val = tag.get(attr)
            if isinstance(val, str) and len(val.strip()) >= 3:
                segments.append(Segment(text=val.strip(), channel=Channel.ATTRIBUTE,
                                        location=f"{location}:<{tag.name} {attr}>", emit=False))
        for attr, val in tag.attrs.items():
            if attr.startswith("data-") and isinstance(val, str) and len(val.strip()) >= 8:
                segments.append(Segment(text=val.strip(), channel=Channel.ATTRIBUTE,
                                        location=f"{location}:<{tag.name} {attr}>", emit=False))
        if tag.name == "meta" and isinstance(tag.get("content"), str) and len(tag["content"]) >= 8:
            name = tag.get("name") or tag.get("property") or "meta"
            if name.lower() not in ("viewport",):
                segments.append(Segment(text=tag["content"], channel=Channel.METADATA,
                                        location=f"{location}:<meta {name}>", emit=False))

    body = "".join(visible).strip()
    return [Segment(text=body, channel=Channel.VISIBLE, location=location)] + segments


def extract_html(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    return extract_html_segments(as_text(data))
