# Firewall_Promptinjection
Project created for ET Hackathon Unstop presented by Accenture

**Prompt Injection Firewall**: a local, deterministic firewall (no LLM in the loop) that inspects everything an AI agent reads, including user messages, web pages, PDFs, Word documents, emails, Markdown, JSON API responses, source code, and images. It detects **all 9 attack types** from the problem statement and neutralizes them before they reach the model.

Target tier: **D3 + F3**. It handles mixed multimodal input and detects 9 of the 9 attack types.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (source .venv/bin/activate on Linux/macOS)
pip install -r requirements.txt

python scripts/make_samples.py    # generate PDF/DOCX/EML/PNG/HTML/... test files
python demo/agent/run_demo.py     # agent demo: same attacks WITHOUT vs WITH the firewall
python scripts/evaluate.py        # reliability report (precision/recall/FPR per type and source)
pytest                            # 97 tests
uvicorn api.main:app --reload     # REST API on http://localhost:8000/docs
```

Optional: install [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki) and add it to PATH. Without it, the firewall still scans an image's metadata, but not the text drawn in its pixels.

## Use it from Python

```python
from firewall import Firewall, Session

fw = Firewall()
r = fw.scan_file("data/samples/attacks/report_white_text.pdf")       # retrieved data -> untrusted
print(r.summary())        # BLOCK risk=1.00 types=[instruction_override, secret_extraction, indirect_injection]
for f in r.findings[:3]:
    print(f.rule_id, f.attack_type.value, f.weighted_score, r.segments[f.segment].location, f.evidence)

r = fw.scan("Summarize this thread for me", source="user", session=Session())
model_input = r.safe_text  # redacted + spotlighted text, or a block notice
```

## How it works

```
input ─► 1 INGEST ─► 2 NORMALIZE/DECODE ─► 3 DETECT ─► 4 POLICY ─► 5 NEUTRALIZE ─► safe_text + verdict
         per-format   unicode, homoglyph,   rules, ML,   trust x      redact, drop hidden,
         hidden-text  base64/rot13/hex...   session,     channel      spotlight, or block
         surfacing                          indirect     weighting
```

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) walks through each stage, the data model, and how to extend it with new rules, formats, or detectors.

## Results

The full report is in [docs/EVALUATION.md](docs/EVALUATION.md); regenerate it with `python scripts/evaluate.py --write`.

| Dataset | Attacks / benign | Precision | Recall | False-positive rate |
|---|---|---|---|---|
| `eval.jsonl` (development set, used while tuning) | 91 / 56 | 1.00 | 1.00 | 0.0% |
| `holdout.jsonl` (written after tuning, never tuned on) | 45 / 26 | 0.95 | 0.78 | 7.7% |
| Multimodal sample files (PDF, DOCX, EML, PNG, HTML, MD, JSON, code) | 14 / 11 | | 24 of 25 correct (the 1 miss is OCR-only, without Tesseract installed) | |

Median scan latency is under 1 ms for text, and a few ms for documents.

**Read the held-out row as the realistic estimate.** Its main weakness is paraphrased direct attacks that the rules don't anticipate. See *Known limitations* in the architecture doc.

## Agent demo

[demo/agent/run_demo.py](demo/agent/run_demo.py) runs a deliberately gullible agent against seven scenarios: hidden email HTML, an invisible web-page div, white text in a PDF, a poisoned API response with base64, a DAN jailbreak, multi-turn payload splitting, and a benign email.

- **Without the firewall**, the agent leaks its system prompt and secrets, emails the inbox to the attacker, and phishes the user (6 of 6 attack scenarios compromised).
- **With the firewall**, all 6 are safe, and the benign email passes through unchanged.

## Layout

```
firewall/          the library: ingest/ normalize/ detectors/ (rules/*.yaml) policy/ pipeline.py guard.py config.yaml
api/main.py        FastAPI wrapper (POST /scan, POST /scan/file)
demo/agent/        mock tools + naive agent + side-by-side runner
data/              train.jsonl (ML), eval.jsonl (dev), holdout.jsonl (test), samples/ (generated files)
scripts/           make_samples.py, evaluate.py
tests/             pytest suite (attack types, benign, extractors, normalization, policy, API, demo)
docs/              ARCHITECTURE.md, EVALUATION.md
```
