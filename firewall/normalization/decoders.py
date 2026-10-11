"""Stage 2b - DECODE.

Finds encoded blobs inside a segment and produces *derived* segments with the decoded
text. Derived segments go through the same detectors, so an instruction hidden as
base64 is caught by the same rules as plain text. Decoding recurses up to
`decoders.max_depth` (e.g. base64 inside url-encoding).

Supported: base64 / base64url, hex, \\xNN escapes, url-encoding, \\uNNNN escapes,
HTML entities, ROT13, reversed text, and s.p.a.c.e.d-o.u.t letters.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import urllib.parse
from dataclasses import dataclass

__all__ = ["find_encoded"]

BASE64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[ :]?){12,}(?![0-9a-fA-F])")
HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}")
UNICODE_ESCAPES = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
HTML_ENTITIES = re.compile(r"(?:&#(?:x[0-9a-fA-F]+|\d+);){4,}")
SPACED = re.compile(r"(?<!\w)(?:\w[ .\-_*|]{1,3}){6,}\w(?!\w)")
URL_TOKEN = re.compile(r"\S+")

COMMON_WORDS = {
    "the", "and", "you", "your", "to", "of", "is", "are", "a", "this", "that", "with", "for", "now", "must",
    "do", "not", "all", "ignore", "instructions", "previous", "system", "prompt", "send", "password", "it",
    "in", "on", "be", "me", "my", "i", "please", "any", "will", "an", "as", "from", "secret", "key", "reveal",
}


@dataclass
class Decoded:
    start: int
    end: int
    text: str
    method: str


def english_score(text: str) -> float:
    words = re.findall(r"[a-z]+", text.lower())
    if not words:
        return 0.0
    return sum(w in COMMON_WORDS for w in words) / len(words)


def _readable(text: str, min_len: int = 6) -> bool:
    if len(text) < min_len:
        return False
    printable = sum(c.isprintable() or c in "\n\r\t" for c in text) / len(text)
    letters = sum(c.isalpha() or c == " " for c in text) / len(text)
    return printable > 0.95 and letters > 0.6 and " " in text.strip()


def _try_base64(blob: str) -> str | None:
    if not (re.search(r"[A-Z]", blob) and re.search(r"[a-z]", blob)) or not re.search(r"[0-9+/=_-]", blob):
        return None
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = fn(blob + "=" * (-len(blob) % 4))
            text = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _readable(text):
            return text
    return None


def _try_hex(blob: str) -> str | None:
    try:
        text = bytes.fromhex(re.sub(r"[ :]|\\x", "", blob)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _readable(text) else None


def find_encoded(text: str, min_base64_len: int = 16) -> list[Decoded]:
    out: list[Decoded] = []
    for m in BASE64.finditer(text):
        if len(m.group(0)) >= min_base64_len and (d := _try_base64(m.group(0))):
            out.append(Decoded(m.start(), m.end(), d, "base64"))
    for pattern in (HEX, HEX_ESCAPES):
        for m in pattern.finditer(text):
            if d := _try_hex(m.group(0)):
                out.append(Decoded(m.start(), m.end(), d, "hex"))
    for m in UNICODE_ESCAPES.finditer(text):
        d = codecs.decode(m.group(0), "unicode_escape")
        if _readable(d, 4):
            out.append(Decoded(m.start(), m.end(), d, "unicode-escape"))
    for m in HTML_ENTITIES.finditer(text):
        d = html.unescape(m.group(0))
        if _readable(d, 4):
            out.append(Decoded(m.start(), m.end(), d, "html-entities"))
    for m in URL_TOKEN.finditer(text):
        tok = m.group(0)
        if tok.count("%") >= 5:
            d = urllib.parse.unquote(tok.replace("+", " "))
            if d != tok and _readable(d, 4):
                out.append(Decoded(m.start(), m.end(), d, "url-encoding"))
    for m in SPACED.finditer(text):
        # single separators sit between letters, wider gaps between words: "i g n o r e   a l l"
        d = re.sub(r"[ .\-_*|]", "", re.sub(r"[ .\-_*|]{2,}", "\x00", m.group(0))).replace("\x00", " ")
        if len(d.replace(" ", "")) >= 7:
            out.append(Decoded(m.start(), m.end(), d, "spaced-letters"))

    # Whole-segment transforms: keep only if the result reads much more like English.
    if len(text) >= 12:
        base = english_score(text)
        for method, transformed in (("rot13", codecs.encode(text, "rot13")), ("reversed", text[::-1])):
            score = english_score(transformed)
            if score >= 0.25 and score > base * 2 + 0.1:
                out.append(Decoded(0, len(text), transformed, method))
    return out
