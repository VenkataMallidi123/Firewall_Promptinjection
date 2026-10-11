"""Stage 2a - NORMALIZE.

Attackers obfuscate text so that keyword filters miss it while the LLM still reads it:
  * fullwidth / mathematical letters  (ｉｇｎｏｒｅ, 𝐢𝐠𝐧𝐨𝐫𝐞)   -> NFKC folds them to ASCII
  * zero-width / bidi control chars   (ig​nore)          -> removed
  * Unicode "tag" characters          (invisible ASCII copy)  -> removed AND decoded (returned separately)
  * homoglyphs                        (Cyrillic 'о' in 'ignоre') -> folded in the *match view*
  * leetspeak                         (1gn0r3)                -> folded in the *match view*

`normalize()` returns the cleaned text that is shown to the model. `match_view()` returns
a same-length, lower-cased, homoglyph/leet-folded copy used only for pattern matching,
so spans found in the match view line up 1:1 with the cleaned text.
"""
from __future__ import annotations

import re
import unicodedata

__all__ = ["match_views", "normalize"]

INVISIBLE = re.compile(
    "[­͏\u061Cᅟᅠ឴឵᠎​-\u200F\u202A-\u202E⁠-⁤\u2066-⁯ㅤ﻿ﾠ]"
)
TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")
HORIZONTAL_WS = re.compile(r"[ \t  -   　]+")

HOMOGLYPHS = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ӏ": "l", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "ԛ": "q", "ԝ": "w", "ɡ": "g",
    # Greek
    "α": "a", "ο": "o", "ε": "e", "ι": "i", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "κ": "k", "χ": "x",
})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
MIXED_SCRIPT_WORD = re.compile(r"\b(?=\w*[a-zA-Z])(?=\w*[Ͱ-ϿЀ-ӿ])\w+\b")


def decode_tag_chars(text: str) -> str:
    """Unicode tag chars U+E0020..E007E mirror printable ASCII and render as nothing."""
    return "".join(chr(ord(c) - 0xE0000) for c in TAG_CHARS.findall(text) if 0x20 <= ord(c) - 0xE0000 <= 0x7E)


def normalize(text: str) -> tuple[str, dict[str, int], str]:
    """Returns (clean_text, obfuscation_flags, smuggled_tag_text)."""
    flags: dict[str, int] = {}
    smuggled = decode_tag_chars(text)
    if smuggled:
        flags["tag_smuggling"] = len(smuggled)
        text = TAG_CHARS.sub("", text)

    nfkc = unicodedata.normalize("NFKC", text)
    if sum(1 for a in text if ord(a) > 0xFF00 or 0x1D400 <= ord(a) <= 0x1D7FF):
        flags["compat_chars"] = 1
    text = nfkc

    # Zero-width chars *inside words* are an obfuscation signal; ZWJ in emoji is not.
    in_word = len(re.findall(r"(?<=\w)" + INVISIBLE.pattern + r"(?=\w)", text))
    if in_word:
        flags["invisible_in_words"] = in_word
    text = INVISIBLE.sub("", text)

    mixed = len(MIXED_SCRIPT_WORD.findall(text))
    if mixed:
        flags["mixed_script_words"] = mixed

    text = HORIZONTAL_WS.sub(" ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip(), flags, smuggled


def _lower_same_length(text: str) -> str:
    return "".join(c.lower() if len(c.lower()) == 1 else c for c in text)


def match_views(text: str) -> list[str]:
    """Same-length views of `text` that detectors match against."""
    lower = _lower_same_length(text)
    folded = lower.translate(HOMOGLYPHS)
    views = [lower]
    if folded != lower:
        views.append(folded)
    leet = folded.translate(LEET)
    if leet != folded:
        views.append(leet)
    return views
