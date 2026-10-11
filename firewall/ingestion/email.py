"""Emails (.eml): subject + body, the HTML part's hidden content, custom headers,
and attachments (recursively extracted with the matching extractor)."""
from __future__ import annotations

from email import policy
from email.parser import BytesParser

from ..core.context import ScanContext
from ..core.models import Channel, Segment, Source
from .base import as_bytes, extend_rebased, extract_nested
from .html import extract_html_segments

__all__ = ["extract_email"]

METADATA_HEADERS = {"reply-to", "comments", "keywords", "organization", "x-mailer"}


def extract_email(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    msg = BytesParser(policy=policy.default).parsebytes(as_bytes(data))
    subject = str(msg.get("subject", "") or "")
    sender = str(msg.get("from", "") or "")

    plain = msg.get_body(preferencelist=("plain",))
    html = msg.get_body(preferencelist=("html",))
    body = plain.get_content() if plain is not None else ""
    html_extra: list[Segment] = []
    if html is not None:
        html_segs = extract_html_segments(html.get_content(), location="email:html")
        if plain is None:
            body = html_segs[0].text
        html_extra = [s for s in html_segs if s.channel is not Channel.VISIBLE]

    header = f"From: {sender}\nSubject: {subject}\n\n" if (sender or subject) else ""
    out = [Segment(text=header + body.strip(), channel=Channel.VISIBLE, location="email:body")]
    out.extend(html_extra)

    for key, value in msg.items():
        k = key.lower()
        if (k.startswith("x-") or k in METADATA_HEADERS) and len(str(value)) >= 3:
            out.append(Segment(text=str(value), channel=Channel.METADATA, location=f"email:header:{key}", emit=False))

    for part in msg.iter_attachments():
        name = part.get_filename() or "attachment"
        try:
            payload = part.get_content()
        except Exception as exc:
            ctx.warnings.append(f"could not decode attachment {name}: {exc}")
            continue
        segs = extract_nested(payload, name, ctx, prefix=f"email:attachment:{name}")
        for seg in segs:
            seg.emit = False  # attachments are reported, not inlined into the body
        extend_rebased(out, segs)
    return out
