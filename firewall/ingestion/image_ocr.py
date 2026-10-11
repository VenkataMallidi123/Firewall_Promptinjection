"""Images: OCR text (via Tesseract, if installed) plus metadata (PNG text chunks, EXIF),
which attackers also use to smuggle instructions to vision-capable agents."""
from __future__ import annotations

import io
from functools import lru_cache

from PIL import ExifTags, Image, ImageOps

from ..core.context import ScanContext
from ..core.models import Channel, Segment, Source
from .base import as_bytes

__all__ = ["extract_image", "tesseract_available"]


@lru_cache(maxsize=1)
def tesseract_available() -> bool:
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def _ocr(img: Image.Image) -> str:
    import pytesseract
    gray = ImageOps.grayscale(img)
    if gray.width < 1000:  # small screenshots OCR better when upscaled
        scale = 1000 / max(gray.width, 1)
        gray = gray.resize((int(gray.width * scale), int(gray.height * scale)))
    text = pytesseract.image_to_string(gray)
    # Light-on-dark and low-contrast text is a common evasion: also OCR the inverted image.
    inverted = pytesseract.image_to_string(ImageOps.invert(gray))
    return text if len(text.strip()) >= len(inverted.strip()) else inverted


def extract_image(data: bytes | str, ctx: ScanContext) -> list[Segment]:
    img = Image.open(io.BytesIO(as_bytes(data)))
    img.load()
    segments: list[Segment] = []
    if tesseract_available():
        text = _ocr(img.convert("RGB"))
        segments.append(Segment(text=text.strip(), channel=Channel.OCR, location="image:ocr"))
    else:
        ctx.warnings.append("OCR skipped: Tesseract binary not found (install it and add to PATH)")
        segments.append(Segment(text="", channel=Channel.OCR, location="image:ocr (skipped)"))

    for key, value in (img.info or {}).items():
        if isinstance(value, str) and len(value.strip()) >= 3:
            segments.append(Segment(text=value, channel=Channel.METADATA, location=f"image:meta:{key}", emit=False))
    try:
        for tag_id, value in img.getexif().items():
            if isinstance(value, bytes):
                value = value.decode("utf-16-le" if tag_id in (0x9C9B, 0x9C9C, 0x9C9D, 0x9C9E, 0x9C9F) else "utf-8", "ignore")
            if isinstance(value, str) and len(value.strip("\x00 ").strip()) >= 3:
                name = ExifTags.TAGS.get(tag_id, hex(tag_id))
                segments.append(Segment(text=value.strip("\x00 "), channel=Channel.METADATA, location=f"image:exif:{name}", emit=False))
    except Exception:
        pass
    return segments
