"""Stage 1 - INGESTION: parse every input format and surface hidden content.

router.py holds the table of which extractor handles which format."""
from .base import detect_source
from .router import extract

__all__ = ["detect_source", "extract"]
