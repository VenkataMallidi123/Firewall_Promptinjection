"""The front door: every interface (REST API, demo CLI, demo web) inspects content through here.

    guard = FirewallGuard()                                    # one guard per conversation
    msg = guard.inspect_user_message(user_text)                # direct injection
    if not msg.allowed: refuse(msg.result)
    obs = guard.inspect_tool_output(raw_bytes, filename="x.eml")   # indirect injection
    model_context += obs.text                                  # redacted + spotlighted, or a block notice

inspect_user_message() and inspect_tool_output() are shortcuts for inspect(), which also lets
the caller choose the source and trust level (the REST API uses it that way).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .core.context import Session
from .core.models import ScanResult, Source, Trust, Verdict
from .pipeline import Firewall

__all__ = ["FirewallGuard"]


@dataclass
class GuardDecision:
    """The answer returned for every inspected piece of content.

    allowed: False only when the verdict is BLOCK.
    text:    what the model may see: the original, a redacted version, or a block notice.
    result:  the full scan report (verdict, risk score, attack types, findings, evidence).
    """
    allowed: bool
    text: str
    result: ScanResult


@dataclass
class FirewallGuard:
    """Checks everything an agent reads before it reaches the model.

    firewall: the 5-stage pipeline that does the inspection (shared between guards is fine).
    session:  conversation memory, used to catch attacks split across several user messages.
    log:      every inspection made, as (label, ScanResult) pairs, for auditing.
    Create one guard per conversation so different users' turns are not mixed.
    """
    firewall: Firewall = field(default_factory=Firewall)
    session: Session = field(default_factory=Session)
    log: list[tuple[str, ScanResult]] = field(default_factory=list)

    def inspect(self, content: bytes | str, source: Source | str | None = None, trust: Trust | str | None = None,
                filename: str | None = None, label: str | None = None) -> GuardDecision:
        """Run any content through the firewall and return a GuardDecision.

        source:   the content type (user, html, pdf, email...); detected from filename/content if omitted.
        trust:    who wrote it; defaults to USER for chat messages and UNTRUSTED for everything else.
        filename: helps detect the format of files and attachments.
        label:    name recorded in the log (defaults to "user" or "tool").
        User messages are added to the conversation memory; tool output is not.
        """
        src = Source(source) if source else None
        tr = Trust(trust) if trust else (Trust.USER if src is Source.USER else Trust.UNTRUSTED)
        session = self.session if tr is Trust.USER else None
        r = self.firewall.scan(content, source=src, trust=tr, filename=filename, session=session)
        self.log.append((label or ("user" if tr is Trust.USER else "tool"), r))
        return GuardDecision(r.verdict is not Verdict.BLOCK, r.safe_text, r)

    def inspect_user_message(self, message: str) -> GuardDecision:
        """Inspect a chat message typed by the user (protects against direct injection)."""
        return self.inspect(message, source=Source.USER, trust=Trust.USER, label="user")

    def inspect_tool_output(self, data: bytes | str, source: Source | str | None = None,
                            filename: str | None = None, tool: str = "tool") -> GuardDecision:
        """Inspect what a tool returned: an email, file, web page or API response (protects
        against indirect injection). Always treated as untrusted; `tool` is the log label."""
        return self.inspect(data, source=source, trust=Trust.UNTRUSTED, filename=filename, label=tool)
