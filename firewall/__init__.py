"""Prompt Injection Firewall - inspects content before it reaches an LLM agent.

Pipeline: ingestion -> normalization -> detection -> decision -> enforcement
(one sub-package per stage; shared types live in firewall/core).
See docs/ARCHITECTURE.md.
"""
from .core.context import Session
from .guard import FirewallGuard
from .core.models import Channel, ScanResult, Source, Trust, Verdict
from .pipeline import Firewall

__all__ = ["Channel", "Firewall", "FirewallGuard", "ScanResult", "Session", "Source", "Trust", "Verdict"]
