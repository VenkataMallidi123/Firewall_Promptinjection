"""Agent integration: put the firewall between the agent and everything it reads.

    guard = FirewallGuard()
    msg = guard.check_user(user_text)                     # direct injection
    if not msg.allowed: refuse(msg.result)
    obs = guard.check_tool_output(raw_bytes, source="email", filename="x.eml")   # indirect injection
    model_context += obs.text                             # redacted + spotlighted, or a block notice
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .context import Session
from .models import ScanResult, Source, Trust, Verdict
from .pipeline import Firewall


@dataclass
class GuardDecision:
    allowed: bool        # False only on BLOCK
    text: str            # what the model may see
    result: ScanResult


@dataclass
class FirewallGuard:
    firewall: Firewall = field(default_factory=Firewall)
    session: Session = field(default_factory=Session)
    log: list[tuple[str, ScanResult]] = field(default_factory=list)

    def check_user(self, message: str) -> GuardDecision:
        r = self.firewall.scan(message, source=Source.USER, trust=Trust.USER, session=self.session)
        self.log.append(("user", r))
        return GuardDecision(r.verdict is not Verdict.BLOCK, r.safe_text, r)

    def check_tool_output(self, data: bytes | str, source: Source | str | None = None,
                          filename: str | None = None, tool: str = "tool") -> GuardDecision:
        r = self.firewall.scan(data, source=source, trust=Trust.UNTRUSTED, filename=filename)
        self.log.append((tool, r))
        return GuardDecision(r.verdict is not Verdict.BLOCK, r.safe_text, r)
