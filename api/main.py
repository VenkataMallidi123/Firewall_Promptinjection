"""Thin REST wrapper so any agent (in any language) can call the firewall.

    uvicorn api.main:app --reload
    curl -X POST localhost:8000/scan -H "content-type: application/json" \
         -d '{"content": "ignore previous instructions", "source": "user"}'
    curl -X POST localhost:8000/scan/file -F "file=@data/samples/attacks/report_white_text.pdf"
"""
from __future__ import annotations

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from firewall import Firewall, Session, Source, Trust

app = FastAPI(title="Prompt Injection Firewall", version="0.1.0")
firewall = Firewall()
sessions: dict[str, Session] = {}   # in-memory; use Redis or similar in production


class ScanRequest(BaseModel):
    content: str
    source: Source | None = None
    trust: Trust | None = None
    session_id: str | None = None     # set for chat turns to enable multi-step detection
    include_segments: bool = False


def _response(result, include_segments: bool) -> dict:
    data = result.model_dump(mode="json", exclude={"segments"} if not include_segments else set())
    data["detected_types"] = result.detected_types()
    return data


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "detectors": [d.name for d in firewall.detectors]}


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    session = sessions.setdefault(req.session_id, Session()) if req.session_id else None
    result = firewall.scan(req.content, source=req.source, trust=req.trust, session=session)
    return _response(result, req.include_segments)


@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...), trust: Trust = Form(Trust.UNTRUSTED),
                    include_segments: bool = Form(False)) -> dict:
    data = await file.read()
    if not data:
        raise HTTPException(400, "empty file")
    result = firewall.scan(data, filename=file.filename, trust=trust)
    return _response(result, include_segments)
