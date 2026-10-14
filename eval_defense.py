"""Ablation harness for the defense layer.

Runs every prompt through every layer independently (``fail_fast=False``) and
reports a confusion matrix per layer, per corpus split, with confidence
intervals.

Three properties this harness enforces, each because getting it wrong produces
a flattering number that is simply false:

1. **Splits never merge.** Every sample carries the corpus it came from, and
   results are reported per split. An earlier version of this file appended the
   extra attack corpus to the scanner's own vectors and reported the union as
   "held-out", which silently folded a 9/9 in-sample score into the
   out-of-sample number and inflated it by 12 points. ``--attacks`` now
   *replaces* the scanner vectors unless ``--include-scanner-attacks`` is
   passed, and the report labels every split as dev or test.

2. **Every rate gets a Wilson interval.** "0% FPR" on 60 samples is consistent
   with a true rate of 6%. Point estimates on corpora this small are not
   decision-grade and the report should not present them as if they were.

3. **Dev and test corpora are distinct, for attacks and benign alike.**
   ``benign_dev.jsonl`` is what the heuristic weights were tuned against, so
   its FPR is a training number by construction. ``benign_test.jsonl`` was
   written afterwards and never tuned against; it is the one to quote.
   ``attacks_dev.jsonl`` holds attacks that were originally filed as held-out
   but whose wording was later copied into heuristic patterns; they are scored
   as in-sample so ``attacks_heldout.jsonl`` stays genuinely unseen.

Usage
-----
    python eval_defense.py                        # default: dev + test splits
    python eval_defense.py --no-classifier        # L1 only, no model weights
    python eval_defense.py --llm-judge            # add the slow semantic layer
    python eval_defense.py --sweep                # threshold sweep (DEV ONLY)
    python eval_defense.py --external attacks.jsonl benign.jsonl
"""
from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import sys

from defense import build_default_pipeline
from scanlog import get_logger, trace_on

# Teaching trace. Silent unless -v/--verbose calls trace_on(); see scanlog.py.
_log = get_logger("eval")

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "defense", "corpus")
BENIGN_DEV = os.path.join(CORPUS, "benign_dev.jsonl")
BENIGN_TEST = os.path.join(CORPUS, "benign_test.jsonl")
ATTACKS_HELDOUT = os.path.join(CORPUS, "attacks_heldout.jsonl")
ATTACKS_DEV = os.path.join(CORPUS, "attacks_dev.jsonl")


# --- statistics -------------------------------------------------------------
def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval.

    Used instead of the normal approximation because these corpora are small and
    the rates of interest sit at the boundaries, where the normal approximation
    produces intervals that include impossible values (a 95% CI of [-3%, 3%] for
    a 0/60 result is not a useful statement).
    """
    if total == 0:
        return (0.0, 1.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def confusion(flags: list[bool], labels: list[int]) -> dict:
    tp = sum(1 for f, y in zip(flags, labels) if f and y == 1)
    fp = sum(1 for f, y in zip(flags, labels) if f and y == 0)
    fn = sum(1 for f, y in zip(flags, labels) if not f and y == 1)
    tn = sum(1 for f, y in zip(flags, labels) if not f and y == 0)

    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * tpr / (precision + tpr)) if (precision + tpr) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "tpr": tpr, "tpr_ci": wilson(tp, tp + fn),
        "fpr": fpr, "fpr_ci": wilson(fp, fp + tn),
        "precision": precision, "f1": f1,
        "n_positive": tp + fn, "n_negative": fp + tn,
    }


# --- corpora ----------------------------------------------------------------
def _read_jsonl(path: str) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_scanner_vectors() -> list[dict]:
    """The scanner's own nine vectors. IN-SAMPLE: L1's patterns were written
    while reading these, so their score measures memorisation, not detection."""
    try:
        from Auto_Prompt_Scanner import ATTACK_VECTORS
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Could not import ATTACK_VECTORS: {exc}", file=sys.stderr)
        return []
    return [{"id": name, "text": payload, "split": "scanner_vectors(DEV)",
             "label": 1} for name, payload in ATTACK_VECTORS.items()]


def load_corpus(path: str, label: int, split: str) -> list[dict]:
    rows = _read_jsonl(path)
    for r in rows:
        r["label"] = label
        r["split"] = split
    return rows


# --- reporting --------------------------------------------------------------
def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _ci(interval: tuple[float, float]) -> str:
    lo, hi = interval
    return f"[{lo * 100:.0f}-{hi * 100:.0f}]"


def format_split_report(split_metrics: dict, latencies: dict) -> str:
    lines = ["=" * 92, "  DEFENSE LAYER ABLATION  (95% Wilson CI in brackets)", "=" * 92]
    for split, layers in split_metrics.items():
        any_layer = next(iter(layers.values()))
        n_pos, n_neg = any_layer["n_positive"], any_layer["n_negative"]
        kind = "attacks" if n_pos else "benign"
        n = n_pos or n_neg
        lines.append(f"\n  {split}   ({n} {kind})")
        if n_pos:
            lines.append(f"    {'layer':<14}{'TPR':>8}{'  95% CI':>12}{'TP':>5}{'FN':>5}"
                         f"{'p50 ms':>10}")
            for name, m in layers.items():
                p50 = latencies.get(name)
                lines.append(f"    {name:<14}{_pct(m['tpr']):>8}{_ci(m['tpr_ci']):>12}"
                             f"{m['tp']:>5}{m['fn']:>5}"
                             f"{(f'{p50:.2f}' if p50 else '-'):>10}")
        else:
            lines.append(f"    {'layer':<14}{'FPR':>8}{'  95% CI':>12}{'FP':>5}{'TN':>5}"
                         f"{'p50 ms':>10}")
            for name, m in layers.items():
                p50 = latencies.get(name)
                lines.append(f"    {name:<14}{_pct(m['fpr']):>8}{_ci(m['fpr_ci']):>12}"
                             f"{m['fp']:>5}{m['tn']:>5}"
                             f"{(f'{p50:.2f}' if p50 else '-'):>10}")
    return "\n".join(lines)


def format_headline(split_metrics: dict) -> str:
    """The two numbers to quote, with their provenance stated."""
    def get(split_key, layer="PIPELINE"):
        for k, v in split_metrics.items():
            if split_key in k:
                return v.get(layer)
        return None

    heldout = get("attacks_heldout")
    dev_atk = get("scanner_vectors")
    dev_corpus = get("attacks_dev")
    ben_test = get("benign_test")
    ben_dev = get("benign_dev")

    out = ["\n" + "=" * 92, "  HEADLINE (quote these, with the caveats)", "=" * 92]
    if dev_atk:
        out.append(f"  IN-SAMPLE detection   {_pct(dev_atk['tpr'])} "
                   f"({dev_atk['tp']}/{dev_atk['n_positive']})  "
                   f"<- patterns were written against these. Not evidence.")
    if dev_corpus:
        out.append(f"  IN-SAMPLE (dev corpus) {_pct(dev_corpus['tpr'])} "
                   f"({dev_corpus['tp']}/{dev_corpus['n_positive']})  "
                   f"<- wording copied into patterns. Not evidence.")
    if heldout:
        out.append(f"  HELD-OUT detection    {_pct(heldout['tpr'])} "
                   f"({heldout['tp']}/{heldout['n_positive']})  "
                   f"95% CI {_ci(heldout['tpr_ci'])}  <- the real number")
    if ben_dev:
        out.append(f"  FPR on tuned benign   {_pct(ben_dev['fpr'])} "
                   f"({ben_dev['fp']}/{ben_dev['n_negative']})  "
                   f"<- fitted to this. Not evidence.")
    if ben_test:
        out.append(f"  FPR on held-out benign {_pct(ben_test['fpr'])} "
                   f"({ben_test['fp']}/{ben_test['n_negative']})  "
                   f"95% CI {_ci(ben_test['fpr_ci'])}  <- the real number")
    out.append("")
    out.append("  Both corpora were written by the same author as the detector.")
    out.append("  Independent validation needs a third-party dataset -- see README.")
    return "\n".join(out)


def format_misses(rows: list[dict]) -> str:
    fns = [r for r in rows if r["label"] == 1 and not r["blocked"]]
    fps = [r for r in rows if r["label"] == 0 and r["blocked"]]
    out = [f"\nMISSED ATTACKS (false negatives): {len(fns)}"]
    for r in fns:
        fam = f" [{r.get('family')}]" if r.get("family") else ""
        out.append(f"  - {r['id']}{fam}: {r['text'][:78].replace(chr(10), ' ')}...")
    out.append(f"\nBLOCKED BENIGN PROMPTS (false positives): {len(fps)}")
    for r in fps:
        note = f"  [{r.get('note')}]" if r.get("note") else ""
        out.append(f"  - {r['id']} ({r['split']}) via {r['triggered_layer']}: "
                   f"{r['text'][:64].replace(chr(10), ' ')}...{note}")
    if not fns and not fps:
        out.append("  (none)")
    return "\n".join(out)


def sweep_thresholds(rows: list[dict], layer_names: list[str]) -> str:
    """Threshold sweep on DEV SPLITS ONLY.

    Choosing a threshold from the same data you then report is how a test set
    becomes a training set. This restricts the sweep to dev so the test numbers
    stay honest; the threshold you pick here is then reported once on test.
    """
    dev = [r for r in rows if "DEV" in r["split"] or r["split"] == "benign_dev"]
    if not dev:
        return "\n(no dev samples to sweep)"
    labels = [r["label"] for r in dev]
    lines = [f"\nTHRESHOLD SWEEP -- DEV SPLITS ONLY ({len(dev)} samples). "
             f"Pick here, report on test."]
    for layer in layer_names:
        scores = [r["layers"][layer]["score"] for r in dev]
        if all(s == 0.0 for s in scores):
            continue
        lines.append(f"\n  {layer}")
        lines.append(f"    {'thresh':>7}{'TPR':>8}{'FPR':>8}{'F1':>7}")
        for t in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
            m = confusion([s >= t for s in scores], labels)
            lines.append(f"    {t:>7.1f}{_pct(m['tpr']):>8}{_pct(m['fpr']):>8}{m['f1']:>7.2f}")
    return "\n".join(lines)


# --- main -------------------------------------------------------------------
def run_eval(pipeline, samples: list[dict]) -> dict:
    rows, latency = [], {n: [] for n in pipeline.layer_names}
    unavailable = set()

    print(f"[-] Evaluating {len(samples)} prompts across layers: "
          f"{', '.join(pipeline.layer_names)}")
    for i, sample in enumerate(samples, 1):
        result = pipeline.check(sample["text"], fail_fast=False)
        for r in result.results:
            latency[r.layer].append(r.latency_ms)
            if not r.available:
                unavailable.add(f"{r.layer}: {r.reason}")
        # One line per sample tying the pipeline's decision to ground truth, so a
        # miss (attack that passed) or false alarm (benign that blocked) is visible
        # as it happens -- the per-layer scoring above shows WHY it dropped or didn't.
        truth = "attack" if sample["label"] == 1 else "benign"
        if result.blocked:
            outcome = f"DROPPED by {result.triggered_layer}"
            correct = sample["label"] == 1
        else:
            outcome = "passed"
            correct = sample["label"] == 0
        _log.info("  [%d/%d] %s (%s) -> %s  %s",
                  i, len(samples), sample.get("split", "?"), truth, outcome,
                  "ok" if correct else "MISS" if sample["label"] == 1 else "FALSE ALARM")
        rows.append({
            **{k: v for k, v in sample.items() if k != "text"},
            "text": sample["text"],
            "blocked": result.blocked,
            "triggered_layer": result.triggered_layer,
            "layers": {r.layer: {"score": round(r.score, 4), "flagged": r.flagged,
                                 "available": r.available}
                       for r in result.results},
        })
        if i % 25 == 0:
            print(f"    ...{i}/{len(samples)}")

    # Per split, per layer, plus the combined pipeline as a pseudo-layer.
    split_metrics: dict[str, dict] = {}
    for split in dict.fromkeys(r["split"] for r in rows):
        subset = [r for r in rows if r["split"] == split]
        labels = [r["label"] for r in subset]
        layers = {n: confusion([r["layers"][n]["flagged"] and r["layers"][n]["available"]
                                for r in subset], labels)
                  for n in pipeline.layer_names}
        layers["PIPELINE"] = confusion([r["blocked"] for r in subset], labels)
        split_metrics[split] = layers

    return {
        "split_metrics": split_metrics,
        "latency_p50_ms": {n: statistics.median(v) for n, v in latency.items() if v},
        "rows": rows,
        "unavailable": sorted(unavailable),
    }


def build_samples(args) -> list[dict]:
    """Assemble the evaluation set. Each corpus becomes its own split.

    ``--attacks`` *replaces* the scanner vectors rather than appending to them;
    the scanner vectors only appear with ``--include-scanner-attacks``, and then
    as a separate in-sample split. Kept out of ``main`` so that rule is testable.
    """
    samples: list[dict] = []
    if args.include_scanner_attacks:
        samples += load_scanner_vectors()
    if args.attacks_dev and os.path.exists(args.attacks_dev):
        samples += load_corpus(args.attacks_dev, 1,
                               f"{os.path.basename(args.attacks_dev)}(DEV)")
    if args.attacks and os.path.exists(args.attacks):
        samples += load_corpus(args.attacks, 1,
                               f"{os.path.basename(args.attacks)}(TEST)")
    if os.path.exists(args.benign_dev):
        samples += load_corpus(args.benign_dev, 0, "benign_dev")
    if os.path.exists(args.benign_test):
        samples += load_corpus(args.benign_test, 0, "benign_test")
    if args.external:
        atk, ben = args.external
        samples += load_corpus(atk, 1, f"external:{os.path.basename(atk)}(TEST)")
        samples += load_corpus(ben, 0, f"external:{os.path.basename(ben)}(TEST)")
    return samples


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Ablate and score the defense layers.")
    ap.add_argument("--no-heuristic", action="store_true")
    ap.add_argument("--no-classifier", action="store_true")
    ap.add_argument("--llm-judge", action="store_true")
    ap.add_argument("--classifier-model", default=None)
    ap.add_argument("--judge-model", default="llama3")
    ap.add_argument("--heuristic-threshold", type=float, default=0.5)
    ap.add_argument("--classifier-threshold", type=float, default=0.5)
    ap.add_argument("--attacks", default=ATTACKS_HELDOUT,
                    help="Held-out attack corpus (REPLACES the scanner vectors "
                         "unless --include-scanner-attacks is given)")
    ap.add_argument("--attacks-dev", default=ATTACKS_DEV,
                    help="In-sample attack corpus, reported as its own DEV split")
    ap.add_argument("--include-scanner-attacks", action="store_true",
                    help="Also score the scanner's own 9 vectors, reported as a "
                         "SEPARATE in-sample split (never merged)")
    ap.add_argument("--benign-dev", default=BENIGN_DEV)
    ap.add_argument("--benign-test", default=BENIGN_TEST)
    ap.add_argument("--external", nargs=2, metavar=("ATTACKS", "BENIGN"),
                    help="Third-party corpora, scored as their own split")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--out", default=os.path.join(HERE, "defense_eval.json"))
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Narrate each prompt as it is scored: per-layer scores and "
                         "where it drops, tied to ground truth (great for a live demo)")
    return ap


def main():
    args = build_parser().parse_args()

    if args.verbose:
        trace_on()

    pipeline = build_default_pipeline(
        use_heuristic=not args.no_heuristic,
        use_classifier=not args.no_classifier,
        use_llm_judge=args.llm_judge,
        classifier_model=args.classifier_model,
        judge_model=args.judge_model,
        heuristic_threshold=args.heuristic_threshold,
        classifier_threshold=args.classifier_threshold,
        fail_fast=False,
    )
    if not pipeline.detectors:
        print("ERROR: every layer disabled.")
        sys.exit(1)

    samples = build_samples(args)
    if not samples:
        print("ERROR: no samples loaded.")
        sys.exit(1)

    report = run_eval(pipeline, samples)

    print()
    print(format_split_report(report["split_metrics"], report["latency_p50_ms"]))
    print(format_headline(report["split_metrics"]))
    print(format_misses(report["rows"]))
    if args.sweep:
        print(sweep_thresholds(report["rows"], pipeline.layer_names))

    if report["unavailable"]:
        print("\n[!] LAYERS THAT COULD NOT RUN (scored as no-detection, so the")
        print("    numbers above UNDERSTATE a fully-installed stack):")
        for msg in report["unavailable"]:
            print(f"      - {msg}")

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[-] Full results written to {args.out}")


if __name__ == "__main__":
    main()
