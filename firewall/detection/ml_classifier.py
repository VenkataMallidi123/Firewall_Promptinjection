"""Optional statistical detector - pure Python, no numpy/scikit-learn.

Rules are precise but only catch phrasings someone wrote a pattern for. This small
model learns from labelled examples (firewall/detection/data/train.jsonl) and adds a generalisation
signal for paraphrased attacks:

  * features   : word unigrams + bigrams (on the homoglyph/leet-folded view)
  * P(attack)  : binary logistic regression trained with SGD
  * attack type: multinomial Naive Bayes over the attack classes

Its score is capped by `ml.max_score`, so on its own it can push content to
SANITIZE but never to BLOCK. Swap in a stronger local model (e.g. a fine-tuned
DeBERTa prompt-injection classifier) by keeping the same detect() contract.
"""
from __future__ import annotations

import json
import math
import random
import re
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path

from ..core.context import ScanContext
from ..core.models import AttackType, Finding, Segment
from ..normalization.unicode import match_views
from .base import Detector, snippet

DEFAULT_TRAIN = Path(__file__).resolve().parent / "data" / "train.jsonl"
TOKEN = re.compile(r"[a-z][a-z']+")
SENTENCE_END = re.compile(r"(?<=[.!?\n])\s+")


def features(text: str) -> Counter:
    words = TOKEN.findall(match_views(text)[-1])
    feats = Counter(words)
    feats.update(f"{a}_{b}" for a, b in zip(words, words[1:]))
    return feats


class TextClassifier:
    def __init__(self, epochs: int = 30, lr: float = 0.2, l2: float = 1e-4, seed: int = 7):
        self.epochs, self.lr, self.l2, self.seed = epochs, lr, l2, seed
        self.w: dict[str, float] = defaultdict(float)
        self.b = 0.0
        self.class_counts: Counter = Counter()
        self.word_counts: dict[str, Counter] = defaultdict(Counter)
        self.vocab: set[str] = set()

    @staticmethod
    def _norm(feats: Counter) -> dict[str, float]:
        n = math.sqrt(sum(v * v for v in feats.values())) or 1.0
        return {k: v / n for k, v in feats.items()}

    def fit(self, texts: list[str], labels: list[str]) -> "TextClassifier":
        data = [(self._norm(features(t)), 1.0 if y != "benign" else 0.0, y) for t, y in zip(texts, labels)]
        # Class-balanced loss: otherwise the bias learns the attack/benign ratio of the
        # training file and unfamiliar text drifts towards "attack".
        n_pos = sum(1 for _, y, _ in data if y) or 1
        n_neg = (len(data) - n_pos) or 1
        weight = {1.0: len(data) / (2 * n_pos), 0.0: len(data) / (2 * n_neg)}
        rng = random.Random(self.seed)
        for _ in range(self.epochs):
            rng.shuffle(data)
            for x, y, _label in data:
                p = self._sigmoid(self.b + sum(self.w[k] * v for k, v in x.items()))
                g = (p - y) * weight[y]
                self.b -= self.lr * g
                for k, v in x.items():
                    self.w[k] -= self.lr * (g * v + self.l2 * self.w[k])
        for t, y in zip(texts, labels):
            if y == "benign":
                continue
            f = features(t)
            self.class_counts[y] += 1
            self.word_counts[y].update(f)
            self.vocab.update(f)
        return self

    @staticmethod
    def _sigmoid(z: float) -> float:
        return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))

    def p_attack(self, text: str) -> float:
        x = self._norm(features(text))
        return self._sigmoid(self.b + sum(self.w.get(k, 0.0) * v for k, v in x.items()))

    def attack_type(self, text: str) -> str:
        f = features(text)
        total = sum(self.class_counts.values())
        v = len(self.vocab) + 1
        best, best_lp = "instruction_override", -math.inf
        for cls, n in self.class_counts.items():
            denom = sum(self.word_counts[cls].values()) + v
            lp = math.log(n / total) + sum(c * math.log((self.word_counts[cls][w] + 1) / denom) for w, c in f.items())
            if lp > best_lp:
                best, best_lp = cls, lp
        return best


@lru_cache(maxsize=4)
def load_model(path: str) -> TextClassifier | None:
    p = Path(path)
    if not p.exists():
        return None
    rows = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
    texts, labels = [], []
    for r in rows:
        text = r["text"] if "text" in r else " ".join(r.get("turns", []))
        texts.append(text)
        labels.append(r["label"])
    return TextClassifier().fit(texts, labels)


def chunks(text: str, size: int) -> list[tuple[int, int]]:
    """Split text into sentence-aligned windows of about `size` characters."""
    spans, start, last = [], 0, 0
    for m in SENTENCE_END.finditer(text):
        if m.end() - start > size and last > start:
            spans.append((start, last))
            start = last
        last = m.end()
    spans.append((start, len(text)))
    return [(a, b) for a, b in spans if text[a:b].strip()]


class MLDetector(Detector):
    name = "ml"

    def __init__(self, config, train_path: Path = DEFAULT_TRAIN):
        super().__init__(config)
        self.cfg = config["ml"]
        self.model = load_model(str(train_path))

    def detect(self, segments: list[Segment], ctx: ScanContext, prior: list[Finding]) -> list[Finding]:
        if self.model is None:
            ctx.warnings.append("ML detector disabled: detection/data/train.jsonl not found")
            return []
        findings: list[Finding] = []
        for i, seg in self.scannable(segments):
            if len(seg.text) < 20:
                continue
            for start, end in chunks(seg.text, self.cfg["chunk_chars"]):
                piece = seg.text[start:end]
                p = self.model.p_attack(piece)
                if p < self.cfg["min_probability"]:
                    continue
                kind = self.model.attack_type(piece)
                findings.append(Finding(
                    attack_type=AttackType(kind), detector=self.name, rule_id="ML",
                    score=round(p * self.cfg["max_score"], 3), segment=i, start=start, end=end,
                    evidence=snippet(seg.text, start, min(end, start + 80), pad=0),
                    description=f"classifier P(attack)={p:.2f}, most similar to {kind}",
                ))
        return findings
