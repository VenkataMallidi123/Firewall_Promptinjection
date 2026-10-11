"""The front door: every interface (REST API, demo CLI, demo web) checks content through here.

    guard = FirewallGuard()                               # one guard per conversation
    msg = guard.check_user(user_text)                     # direct injection
    if not msg.allowed: refuse(msg.result)
    obs = guard.check_tool_output(raw_bytes, filename="x.eml")   # indirect injection
    model_context += obs.text                             # redacted + spotlighted, or a block notice

check_user() and check_tool_output() are shortcuts for check(), which also lets the caller
choose the source and trust level (the REST API uses it that way).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .core.context import Session
from .core.models import ScanResult, Source, Trust, Verdict
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

    def check(self, content: bytes | str, source: Source | str | None = None, trust: Trust | str | None = None,
              filename: str | None = None, label: str | None = None) -> GuardDecision:
        """Scan any content. User turns are remembered in the session (multi-turn detection)."""
        src = Source(source) if source else None
        tr = Trust(trust) if trust else (Trust.USER if src is Source.USER else Trust.UNTRUSTED)
        session = self.session if tr is Trust.USER else None
        r = self.firewall.scan(content, source=src, trust=tr, filename=filename, session=session)
        self.log.append((label or ("user" if tr is Trust.USER else "tool"), r))
        return GuardDecision(r.verdict is not Verdict.BLOCK, r.safe_text, r)

    def check_user(self, message: str) -> GuardDecision:
        return self.check(message, source=Source.USER, trust=Trust.USER, label="user")

    def check_tool_output(self, data: bytes | str, source: Source | str | None = None,
                          filename: str | None = None, tool: str = "tool") -> GuardDecision:
        return self.check(data, source=source, trust=Trust.UNTRUSTED, filename=filename, label=tool)
