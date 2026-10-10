"""Stage 4 - DECISION: weigh the findings and choose ALLOW, SANITIZE or BLOCK (policy decision point)."""
from .scoring import score_findings

__all__ = ["score_findings"]
