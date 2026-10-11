"""REST API: lets any agent or application, in any language, call the firewall over HTTP.

    uvicorn interfaces.rest_api.main:app --reload
    curl -X POST localhost:8000/scan -H "content-type: application/json" \
         -d '{"content": "ignore previous instructions", "source": "user"}'
    curl -X POST localhost:8000/scan/file -F "file=@testing/samples/attacks/report_white_text.pdf"

Like every interface, it checks content through FirewallGuard: one guard per session_id,
so multi-turn attacks across a conversation are detected.
"""
from __future__ import annotations

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from firewall import Firewall, FirewallGuard, Source, Trust

app = FastAPI(title="Prompt Injection Firewall", version="0.1.0")
firewall = Firewall()                        # one pipeline, shared by every guard
guards: dict[str, FirewallGuard] = {}        # one guard per session_id; in-memory (use Redis or similar in production)


class ScanRequest(BaseModel):
    content: str
    source: Source | None = None
    trust: Trust | None = None
    session_id: str | None = None     # set for chat turns to enable multi-step detection
    include_segments: bool = False


def _guard(session_id: str | None) -> FirewallGuard:
    """The conversation's guard, or a one-off guard when no session is given."""
    if session_id is None:
        return FirewallGuard(firewall=firewall)
    return guards.setdefault(session_id, FirewallGuard(firewall=firewall))


def _response(result, include_segments: bool) -> dict:
    data = result.model_dump(mode="json", exclude={"segments"} if not include_segments else set())
    data["detected_types"] = result.detected_types()
    return data


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "detectors": [d.name for d in firewall.detectors]}


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    decision = _guard(req.session_id).check(req.content, source=req.source, trust=req.trust)
    return _response(decision.result, req.include_segments)


@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...), trust: Trust = Form(Trust.UNTRUSTED),
                    include_segments: bool = Form(False)) -> dict:
    data = await file.read()
    if not data:
        raise HTTPException(400, "empty file")
    decision = _guard(None).check(data, filename=file.filename, trust=trust, label=file.filename)
    return _response(decision.result, include_segments)
