"""Web interface for the agent demo (separate from the firewall's own REST API).

    python demo_ui/server.py          # then open http://localhost:8001
    uvicorn demo_ui.server:app --port 8001 --reload
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, File, Form, HTTPException, UploadFile  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402

import runner  # noqa: E402
from firewall import Firewall  # noqa: E402

MAX_UPLOAD = 10 * 1024 * 1024
STATIC = Path(__file__).with_name("static")

app = FastAPI(title="Prompt Injection Firewall - Agent Demo")
firewall = Firewall()


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/scenarios")
def list_scenarios() -> list[dict]:
    return runner.scenarios()


@app.get("/api/samples")
def list_samples() -> dict:
    return runner.sample_files()


@app.post("/api/run/{sid}")
def run_scenario(sid: int) -> dict:
    if not 1 <= sid <= runner.scenario_count():
        raise HTTPException(404, "unknown scenario")
    files, turns = runner.scenario(sid)
    return {"turns": turns, **runner.compare(files, turns, firewall)}


@app.post("/api/run-custom")
async def run_custom(messages: str = Form(...), sample: str = Form(""),
                     file: UploadFile | None = File(None)) -> dict:
    # Turns are separated by a line containing only "---".
    turns = [t.strip() for t in messages.replace("\r\n", "\n").split("\n---\n") if t.strip()]
    if not turns:
        raise HTTPException(400, "enter at least one message")
    source: dict | tuple[bytes, str] = {}
    if file is not None and file.filename:
        data = await file.read()
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, "file larger than 10 MB")
        source = (data, file.filename)
    elif sample:
        try:
            source = runner.read_sample(sample)
        except FileNotFoundError:
            raise HTTPException(404, "unknown sample file")
    return {"turns": turns, **runner.compare(source, turns, firewall)}


if __name__ == "__main__":
    import uvicorn
    print("Agent demo UI: http://localhost:8001")
    uvicorn.run(app, host="127.0.0.1", port=8001)
