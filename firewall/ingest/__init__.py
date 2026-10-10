"""Importing the extractor modules registers them with the ingest registry."""
from . import api_json, code, docx, email, html, image_ocr, markdown, pdf, text  # noqa: F401
from .base import detect_source, extract, register

__all__ = ["detect_source", "extract", "register"]
