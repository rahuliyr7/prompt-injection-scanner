"""Compute Attack Success Rate (ASR) from a scanner run's results.jsonl.

ASR is the share of attempts where the attack got through -- i.e. the verdict is
``success``. This tool prints an overall ASR plus per-vector and per-OWASP
breakdowns.

Usage:
    python metrics.py runs/latest/results.jsonl
"""
import sys
import json
import argparse


def load_results(path):
    """Read a JSONL file into a list of dicts, skipping blank lines."""
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _rate(rows):
    attempts = len(rows)
    successes = sum(1 for r in rows if r.get("verdict") == "success")
    asr = successes / attempts if attempts else 0.0
    return {"attempts": attempts, "successes": successes, "asr": asr}


def _group_by(rows, key):
    groups = {}
    for r in rows:
        groups.setdefault(r.get(key, "unknown"), []).append(r)
    return {name: _rate(group) for name, group in sorted(groups.items())}


def compute_asr(rows):
    """Return overall ASR plus per-vector and per-OWASP breakdowns (pure/testable)."""
    return {
        "overall": _rate(rows),
        "by_vector": _group_by(rows, "vector"),
        "by_owasp": _group_by(rows, "owasp"),
    }


def _format_section(title, col_header, breakdown):
    lines = [f"\n{title}", f"  {col_header:<24} {'ASR':>7}   attempts"]
    for name, stats in breakdown.items():
        lines.append(f"  {name:<24} {stats['asr'] * 100:6.1f}%   "
                     f"{stats['successes']}/{stats['attempts']}")
    return "\n".join(lines)


def format_report(metrics):
    overall = metrics["overall"]
    out = [
        "=" * 44,
        "  ATTACK SUCCESS RATE (ASR)",
        "=" * 44,
        f"  Overall: {overall['asr'] * 100:.1f}%  "
        f"({overall['successes']}/{overall['attempts']} attacks succeeded)",
    ]
    out.append(_format_section("Per vector:", "vector", metrics["by_vector"]))
    out.append(_format_section("Per OWASP category:", "owasp", metrics["by_owasp"]))
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Compute ASR from a results.jsonl file.")
    parser.add_argument("results", help="Path to a run's results.jsonl")
    args = parser.parse_args()

    try:
        rows = load_results(args.results)
    except FileNotFoundError:
        print(f"ERROR: no such file: {args.results}")
        sys.exit(1)

    if not rows:
        print(f"No results found in {args.results}")
        sys.exit(1)

    print(format_report(compute_asr(rows)))


if __name__ == "__main__":
    main()
