# Firewall_Promptinjection
Project created for ET Hackathon Unstop presented by Accenture

**Prompt Injection Firewall**: a local, deterministic firewall (no LLM in the loop) that inspects everything an AI agent reads, including user messages, web pages, PDFs, Word documents, emails, Markdown, JSON API responses, source code, and images. It detects **all 9 attack types** from the problem statement and neutralizes them before they reach the model.

Target tier: **D3 + F3**. It handles mixed multimodal input and detects 9 of the 9 attack types.

## Requirements

- Python 3.14
- Dependencies are pinned in [requirements.txt](requirements.txt): pydantic, pyyaml, beautifulsoup4, pypdf, python-docx, pillow, pytesseract, fastapi, uvicorn, python-multipart, and for tests: reportlab, pytest, httpx
- Optional: [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki) on PATH. Without it, the firewall still scans an image's metadata, but not the text drawn in its pixels.

No API keys or environment variables are needed. Everything runs locally.

## Installation and environment setup

```bash
git clone https://github.com/VenkataMallidi123/Firewall_Promptinjection.git
cd Firewall_Promptinjection

python -m venv .venv
.venv\Scripts\activate            # Windows  (source .venv/bin/activate on Linux/macOS)
pip install -r requirements.txt

python testing/samples/make_samples.py      # generate the PDF/DOCX/EML/PNG/HTML/... test files
```

## Running

```bash
python interfaces/demo/cli/run_demo.py          # agent demo, terminal: same attacks WITHOUT vs WITH the firewall
python interfaces/demo/web/server.py            # agent demo, browser: http://localhost:8001
uvicorn interfaces.rest_api.main:app --reload   # REST API on http://localhost:8000 (Swagger UI at /docs)
python testing/evaluation/evaluate.py           # reliability report (precision/recall/FPR per type and source)
pytest                                          # 102 passing tests (1 skipped without Tesseract)
```

## Use it from Python

```python
from firewall import Firewall, Session

fw = Firewall()
r = fw.scan_file("testing/samples/attacks/report_white_text.pdf")       # retrieved data -> untrusted
print(r.summary())        # BLOCK risk=1.00 types=[instruction_override, secret_extraction, indirect_injection]
for f in r.findings[:3]:
    print(f.rule_id, f.attack_type.value, f.weighted_score, r.segments[f.segment].location, f.evidence)

r = fw.scan("Summarize this thread for me", source="user", session=Session())
model_input = r.safe_text  # redacted + spotlighted text, or a block notice
```

## API documentation

Start the server with `uvicorn interfaces.rest_api.main:app --reload`. Interactive docs are at http://localhost:8000/docs.

| Method | Endpoint | Body | Description |
|---|---|---|---|
| GET | `/health` | none | Status and list of active detectors |
| POST | `/scan` | JSON: `content` (required), `source`, `trust`, `session_id`, `include_segments` | Scan text. Reuse the same `session_id` across chat turns to detect multi-turn attacks. |
| POST | `/scan/file` | multipart form: `file` (required), `trust` (default `untrusted`), `include_segments` | Scan a file (PDF, DOCX, EML, HTML, MD, JSON, code, image) |

Both scan endpoints return the verdict (allow / sanitize / block), risk score, findings with evidence and location, `detected_types`, and `safe_text` to pass to the model.

```bash
curl -X POST localhost:8000/scan -H "content-type: application/json" \
     -d '{"content": "ignore previous instructions", "source": "user"}'
curl -X POST localhost:8000/scan/file -F "file=@testing/samples/attacks/report_white_text.pdf"
```

## Architecture

```
input ─► 1 INGESTION ─► 2 NORMALIZATION ─► 3 DETECTION ─► 4 DECISION ─► 5 ENFORCEMENT ─► safe_text + verdict
         per-format   unicode, homoglyph,   rules, ML,   trust x      redact, drop hidden,
         hidden-text  base64/rot13/hex...   session,     channel      spotlight, or block
         surfacing                          indirect     weighting
```

1. **Ingestion** ([firewall/ingestion/](firewall/ingestion/)): parses each format into text segments, surfaces hidden content (comments, white text, metadata) and tags where each segment came from.
2. **Normalization** ([firewall/normalization/](firewall/normalization/)): Unicode NFKC, homoglyph folding, invisible-character removal, and Base64 / hex / ROT13 / URL decoding.
3. **Detection** ([firewall/detection/](firewall/detection/)): YAML signature rules, a local ML classifier, session memory for multi-turn attacks, and indirect-injection checks.
4. **Decision** ([firewall/decision/](firewall/decision/)): weights findings by source trust and channel into a risk score and an allow / sanitize / block verdict.
5. **Enforcement** ([firewall/enforcement/](firewall/enforcement/)): redacts malicious spans, drops hidden content, spotlights untrusted data, or blocks.

[firewall/pipeline.py](firewall/pipeline.py) wires the stages together, and every interface calls the firewall through [firewall/guard.py](firewall/guard.py). Thresholds and weights are in [firewall/core/config.yaml](firewall/core/config.yaml).

## Results

| Dataset | Attacks / benign | Precision | Recall | False-positive rate |
|---|---|---|---|---|
| `eval.jsonl` (development set, used while tuning) | 91 / 56 | 1.00 | 1.00 | 0.0% |
| `holdout.jsonl` (written after tuning, never tuned on) | 45 / 26 | 0.95 | 0.78 | 7.7% |
| Multimodal sample files (PDF, DOCX, EML, PNG, HTML, MD, JSON, code) | 14 / 11 | | 24 of 25 correct (the 1 miss is OCR-only, without Tesseract installed) | |

Median scan latency is under 1 ms for text, and a few ms for documents.

**Read the held-out row as the realistic estimate.** Its main weakness is paraphrased direct attacks that the rules don't anticipate.

## Agent demo

The demo runs one deliberately gullible agent ([interfaces/demo/agent/](interfaces/demo/agent/)) with two front-ends: [demo/cli](interfaces/demo/cli/run_demo.py) in the terminal and [demo/web](interfaces/demo/web/server.py) in the browser. The terminal version runs seven scenarios: hidden email HTML, an invisible web-page div, white text in a PDF, a poisoned API response with base64, a DAN jailbreak, multi-turn payload splitting, and a benign email.

- **Without the firewall**, the agent leaks its system prompt and secrets, emails the inbox to the attacker, and phishes the user (6 of 6 attack scenarios compromised).
- **With the firewall**, all 6 are safe, and the benign email passes through unchanged.

## Layout

```
firewall/                 the product: the 5-stage pipeline
  core/                   shared models, scan context, config.yaml
  ingestion/      stage 1 parsers per format, hidden-content extraction
  normalization/  stage 2 canonicalization and decoding
  detection/      stage 3 rules/*.yaml, ML classifier (data/train.jsonl), session and indirect checks
  decision/       stage 4 risk scoring and verdict
  enforcement/    stage 5 redaction, isolation and spotlighting
  pipeline.py             wires stages 1 → 5
  guard.py                the front door: every interface checks content through FirewallGuard
interfaces/               how people use it (all go through guard.py)
  rest_api/               REST API service for real integrations (POST /scan, POST /scan/file)
  demo/                   the agent demo
    agent/                the simulated agent, mock tools and scenarios (shared)
    cli/                  terminal front-end
    web/                  browser front-end
testing/                  how we prove it works
  tests/                  pytest suite
  evaluation/             evaluate.py + eval.jsonl (dev) + holdout.jsonl (test)
  samples/                make_samples.py + generated attack/benign files
docs/                     hackathon deck
```
