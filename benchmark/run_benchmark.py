#!/usr/bin/env python3
"""
run_benchmark.py -- score the static detector against the labeled synthetic benchmark.

Reports two complementary views and writes benchmark/results.md:

  * Detection (binary): treat the detector as malicious-vs-benign at the REVIEW threshold
    (label is not None OR score >= 40). Yields precision / recall / F1 + a confusion matrix.
  * Labeling (exactness): does classify() assign the expected label? This exposes the
    deliberately conservative cases -- real vectors the high-precision classifier leaves
    unlabeled (surfaced only via score), which are detection-true-positives but label-misses.

Everything is synthetic (see dataset.json -> corpus/). No network, no real postings.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "scanner"))
import detect as DET

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, os.pardir, "scanner", "corpus")
REVIEW_THRESHOLD = 40


def load():
    with open(os.path.join(HERE, "dataset.json"), encoding="utf-8") as f:
        return json.load(f)["cases"]


def evaluate(cases):
    rows = []
    for c in cases:
        with open(os.path.join(CORPUS, c["file"]), encoding="utf-8") as f:
            findings = DET.detect(f.read())
        label, _ = DET.classify(findings)
        score = DET.score(findings)
        predicted_positive = (label is not None) or (score >= REVIEW_THRESHOLD)
        rows.append({**c, "label": label, "score": score,
                     "predicted_positive": predicted_positive,
                     "label_exact": label == c["expected_label"]})
    return rows


def metrics(rows):
    tp = sum(r["predicted_positive"] and r["malicious"] for r in rows)
    fp = sum(r["predicted_positive"] and not r["malicious"] for r in rows)
    fn = sum((not r["predicted_positive"]) and r["malicious"] for r in rows)
    tn = sum((not r["predicted_positive"]) and not r["malicious"] for r in rows)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    label_acc = sum(r["label_exact"] for r in rows) / max(1, len(rows))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision,
            "recall": recall, "f1": f1, "label_accuracy": label_acc, "n": len(rows)}


def render_markdown(rows, m):
    lines = ["# Benchmark results", "",
             "Static detector vs the synthetic labeled benchmark (`dataset.json`). Regenerate with "
             "`python3 benchmark/run_benchmark.py`.", "",
             "## Detection (malicious vs benign, REVIEW threshold)", "",
             f"- **Precision:** {m['precision']:.3f}",
             f"- **Recall:** {m['recall']:.3f}",
             f"- **F1:** {m['f1']:.3f}",
             f"- Confusion: TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']} (n={m['n']})",
             f"- **Label exactness:** {m['label_accuracy']:.3f} "
             "(classify() assigns exactly the expected label, incl. the deliberately-unlabeled cases)", "",
             "## Per-case", "",
             "| id | vector | malicious | expected | label | score | detected | label_exact |",
             "|----|--------|-----------|----------|-------|------:|:--------:|:-----------:|"]
    for r in rows:
        lines.append(f"| {r['id']} | {r['vector']} | {r['malicious']} | {r['expected_label']} | "
                     f"{r['label']} | {r['score']} | {'✓' if r['predicted_positive'] else '·'} | "
                     f"{'✓' if r['label_exact'] else '·'} |")
    lines += ["",
              "**Reading the table:** cases with `expected = null` are real injection vectors the "
              "high-precision `classify()` intentionally does **not** auto-label (e.g. bare HTML "
              "comments, attribute injection, zero-width) to avoid false positives. They are still "
              "*detected* — they cross the score threshold (`detected = ✓`) — so they count as "
              "detection true-positives while remaining unlabeled. That separation between "
              "*detection* and *auto-labeling* is the precision/recall trade-off made explicit; the "
              "benchmark pins both so a refactor can't quietly shift it.", ""]
    return "\n".join(lines)


def main():
    rows = evaluate(load())
    m = metrics(rows)
    out = render_markdown(rows, m)
    with open(os.path.join(HERE, "results.md"), "w", encoding="utf-8") as f:
        f.write(out + "\n")
    print(out)
    print(f"\nwrote {os.path.join('benchmark', 'results.md')}")


if __name__ == "__main__":
    main()
