"""Prompt Injection Firewall - inspects content before it reaches an LLM agent.

Pipeline: ingestion -> normalization -> detection -> decision -> enforcement
(one sub-package per stage; shared types live in firewall/core).
See docs/ARCHITECTURE.md.
"""
from .core.context import Session
from .guard import FirewallGuard, GuardDecision
from .core.models import AttackType, Channel, Finding, ScanResult, Segment, Source, Trust, Verdict
from .pipeline import Firewall

__all__ = ["Firewall", "FirewallGuard", "GuardDecision", "Session", "AttackType", "Channel", "Finding",
           "ScanResult", "Segment", "Source", "Trust", "Verdict"]
