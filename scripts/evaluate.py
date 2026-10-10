"""Reliability report for the firewall.

    python scripts/evaluate.py              # eval.jsonl + holdout.jsonl + data/samples/
    python scripts/evaluate.py --misses     # also list every miss / false positive
    python scripts/evaluate.py --write      # also save the report to docs/EVALUATION.md
    python scripts/evaluate.py --data my.jsonl   # any JSONL with {"text"|"turns", "label", "source"}

"Detected" means the verdict was SANITIZE or BLOCK. "Type identified" means the labelled
attack type was among the types the firewall reported (score >= 0.3).

Datasets: train.jsonl trains the ML detector; eval.jsonl was used while tuning rules
(a development set, so its score is optimistic); holdout.jsonl was written afterwards
and never tuned on - it is the honest estimate. Add third-party datasets for more.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from firewall import Firewall, Session, Verdict  # noqa: E402

ATTACK_TYPES = ["instruction_override", "role_change", "secret_extraction", "tool_abuse", "credential_theft",
                "context_poisoning", "multi_step_jailbreak", "encoded_instructions", "indirect_injection"]


def as_eml(text: str) -> str:
    """Eval rows store emails as 'Subject: ...\\nbody'; wrap them into a minimal RFC-822 message."""
    subject = "(no subject)"
    if text.startswith("Subject:"):
        first, _, text = text.partition("\n")
        subject = first[len("Subject:"):].strip()
    return f"From: sender@example.com\nTo: user@example.com\nSubject: {subject}\nContent-Type: text/plain; charset=utf-8\n\n{text}"


def run_row(fw: Firewall, row: dict) -> tuple[bool, set[str], float, str]:
    source = row.get("source", "text")
    turns = row.get("turns") or [row["text"]]
    session = Session() if "turns" in row else None
    detected, types, latency, summary = False, set(), 0.0, ""
    for turn in turns:
        content = as_eml(turn) if source == "email" else turn
        r = fw.scan(content, source=source, trust=row.get("trust"), session=session)
        detected |= r.verdict is not Verdict.ALLOW
        types |= set(r.detected_types())
        latency += r.elapsed_ms
        summary = r.summary()
    return detected, types, latency, summary


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:5.1f}%" if b else "  n/a"


DATASETS = {
    "eval.jsonl": "development set - rules/thresholds were tuned while looking at these results",
    "holdout.jsonl": "held-out set - written after tuning and never used to change the firewall",
}


def evaluate_dataset(fw: Firewall, path: Path, show_misses: bool) -> list[str]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    tp = fn = fp = tn = 0
    by_label = defaultdict(lambda: [0, 0, 0])   # detected, type_hit, total
    by_source = defaultdict(lambda: [0, 0, 0, 0])  # tp, attacks, fp, benign
    latencies, misses = [], []

    for row in rows:
        label = row["label"]
        detected, types, latency, summary = run_row(fw, row)
        latencies.append(latency)
        src = by_source[row.get("source", "text")]
        if label == "benign":
            src[3] += 1
            if detected:
                fp += 1
                src[2] += 1
                misses.append(f"FALSE POSITIVE  [{row.get('source')}] {summary} :: {(row.get('text') or row['turns'][-1])[:90]!r}")
            else:
                tn += 1
        else:
            src[1] += 1
            stats = by_label[label]
            stats[2] += 1
            if detected:
                tp += 1
                src[0] += 1
                stats[0] += 1
                if label in types:
                    stats[1] += 1
                else:
                    misses.append(f"WRONG TYPE      [{label}] got {sorted(types)} :: {(row.get('text') or row['turns'][-1])[:90]!r}")
            else:
                fn += 1
                misses.append(f"MISSED          [{label}] {summary} :: {(row.get('text') or row['turns'][-1])[:90]!r}")

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    out = [f"## Text benchmark: {path.name} ({tp + fn} attacks, {fp + tn} benign)", "",
           f"_{DATASETS.get(path.name, 'custom dataset')}_", "",
           "| metric | value |", "|---|---|",
           f"| precision | {precision:.3f} |", f"| recall (detection rate) | {recall:.3f} |", f"| F1 | {f1:.3f} |",
           f"| false-positive rate | {fp / (fp + tn) if fp + tn else 0:.3f} ({fp}/{fp + tn}) |",
           f"| mean latency | {statistics.mean(latencies):.2f} ms |",
           f"| p95 latency | {sorted(latencies)[int(0.95 * (len(latencies) - 1))]:.2f} ms |", "",
           "### Per attack type", "", "| attack type | detected | type identified |", "|---|---|---|"]
    for t in ATTACK_TYPES:
        d, h, n = by_label[t]
        out.append(f"| {t} | {d}/{n} ({pct(d, n).strip()}) | {h}/{n} ({pct(h, n).strip()}) |")
    out += ["", "### Per input source", "", "| source | attacks detected | benign false positives |", "|---|---|---|"]
    for s, (t_p, a, f_p, b) in sorted(by_source.items()):
        out.append(f"| {s} | {t_p}/{a} | {f_p}/{b} |")
    if show_misses and misses:
        out += ["", "### Misses and false positives", "", *[f"- `{m}`" for m in misses]]
    return out


def evaluate_samples(fw: Firewall, folder: Path) -> list[str]:
    if not folder.exists():
        return ["", "_data/samples not found - run `python scripts/make_samples.py` first._"]
    out = ["", "## File samples (multimodal)", "", "| file | expected | verdict | risk | types | notes |", "|---|---|---|---|---|---|"]
    ok = total = 0
    for kind in ("attacks", "benign"):
        for path in sorted((folder / kind).glob("*")):
            r = fw.scan_file(path)
            expected = "detect" if kind == "attacks" else "allow"
            passed = (r.verdict is not Verdict.ALLOW) == (kind == "attacks")
            ok += passed
            total += 1
            notes = "; ".join(r.warnings)[:60]
            out.append(f"| {kind}/{path.name} | {expected} | {'PASS ' if passed else 'FAIL '}{r.verdict.value} | "
                       f"{r.risk_score:.2f} | {', '.join(r.detected_types()[:3])} | {notes} |")
    out.insert(3, f"{ok}/{total} files handled correctly.\n")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", action="append", help="JSONL dataset(s); default: eval.jsonl and holdout.jsonl")
    ap.add_argument("--misses", action="store_true")
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to cp1252

    fw = Firewall()
    lines = ["# Firewall evaluation report", ""]
    for data in args.data or [ROOT / "data" / name for name in DATASETS]:
        lines += evaluate_dataset(fw, Path(data), args.misses) + [""]
    lines += evaluate_samples(fw, ROOT / "data" / "samples")
    report = "\n".join(lines)
    print(report)
    if args.write:
        (ROOT / "docs").mkdir(exist_ok=True)
        (ROOT / "docs" / "EVALUATION.md").write_text(report + "\n", encoding="utf-8")
        print("\nwritten to docs/EVALUATION.md")


if __name__ == "__main__":
    main()
