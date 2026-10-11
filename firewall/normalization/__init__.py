"""Stage 2 - NORMALIZATION: canonicalize every segment, then append decoded child segments."""
from __future__ import annotations

from ..core.context import ScanContext
from ..core.models import Channel, Segment
from .decoders import find_encoded
from .unicode import normalize

__all__ = ["expand_decoded", "normalize_segments"]


def normalize_segments(segments: list[Segment], ctx: ScanContext) -> list[Segment]:
    """Clean each segment in place. Text smuggled in invisible Unicode tag characters
    is recovered and appended as a hidden child segment."""
    out = list(segments)
    for i, seg in enumerate(segments):
        if not seg.scan:
            continue  # container text (full code / JSON) stays byte-exact; its children are scanned
        clean, flags, smuggled = normalize(seg.text)
        seg.text = clean
        seg.flags.update(flags)
        if smuggled:
            out.append(Segment(text=smuggled, channel=Channel.DECODED, location=f"{seg.location} (unicode tag chars)",
                               depth=seg.depth + 1, parent=i, parent_span=(0, len(clean)),
                               decoded_from="unicode-tags", emit=False, flags={"tag_smuggling": len(smuggled)}))
            ctx.log(f"recovered {len(smuggled)} smuggled tag chars from segment {i}")
    return out


def expand_decoded(segments: list[Segment], ctx: ScanContext) -> list[Segment]:
    """Breadth-first decoding: each pass decodes the segments produced by the last."""
    cfg = ctx.config["decoders"]
    limit = ctx.config["limits"]["max_segments"]
    out = list(segments)
    frontier = list(range(len(out)))
    for _ in range(cfg["max_depth"]):
        new: list[int] = []
        for i in frontier:
            seg = out[i]
            if not seg.scan or not seg.text:
                continue
            for d in find_encoded(seg.text, cfg["min_base64_len"]):
                clean, flags, _ = normalize(d.text)
                if not clean or clean == seg.text:
                    continue
                out.append(Segment(text=clean, channel=Channel.DECODED, location=f"{seg.location} ({d.method})",
                                   depth=seg.depth + 1, parent=i, parent_span=(d.start, d.end),
                                   decoded_from=d.method, emit=False, flags=flags))
                new.append(len(out) - 1)
                ctx.log(f"decoded {d.method} in segment {i} -> segment {len(out) - 1}")
                if len(out) >= limit:
                    ctx.warnings.append("segment limit reached while decoding")
                    return out
        frontier = new
        if not frontier:
            break
    return out
