"""Prompt Injection Firewall - inspects content before it reaches an LLM agent.

Pipeline: ingest -> normalize/decode -> detect -> policy -> neutralize.
See docs/ARCHITECTURE.md.
"""
from .context import Session
from .guard import FirewallGuard, GuardDecision
from .models import AttackType, Channel, Finding, ScanResult, Segment, Source, Trust, Verdict
from .pipeline import Firewall

__all__ = ["Firewall", "FirewallGuard", "GuardDecision", "Session", "AttackType", "Channel", "Finding",
           "ScanResult", "Segment", "Source", "Trust", "Verdict"]
