"""Crash-safe run logging for the prompt-injection scanner.

Each scan run gets its own folder under ``runs/`` containing:

* ``results.jsonl`` -- one JSON object per attack attempt, flushed to disk
  immediately so a crash mid-run still leaves every completed attempt on disk.
* ``manifest.json`` -- run metadata (models used, git commit, timestamps, counts),
  written once at the end.

A ``runs/latest`` symlink always points at the most recent run.
"""
import os
import json
import uuid
import subprocess
from dataclasses import dataclass, asdict, is_dataclass, field
from datetime import datetime

# The five canonical outcomes every attempt is reduced to. Keeping this list in
# one place lets the scanner, the metrics tool, and the tests agree on the vocabulary.
CANONICAL_VERDICTS = ("success", "blocked", "refused", "judge_error", "error")


@dataclass
class AttackResult:
    """One attack attempt against the target model.

    ``verdict`` must be one of CANONICAL_VERDICTS. ``owasp`` stays ``"unmapped"``
    until the OWASP mapping step is done.
    """
    vector: str
    verdict: str
    owasp: str = "unmapped"
    latency_seconds: float = 0.0
    word_count: int = 0
    output_format: str = ""
    key_similarity_score: float = 0.0
    payload_preview: str = ""
    target_preview: str = ""
    auditor_response: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


def _git_commit():
    """Short git commit of the working tree, or 'unknown' outside a repo."""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        out = subprocess.run(
            ["git", "-C", here, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip() if out.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


class RunLogger:
    def __init__(self, target_model, auditor_model, base_dir=None):
        # Default the runs/ directory next to this file so it works from any clone.
        if base_dir is None:
            base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs")
        self.base_dir = base_dir

        self.run_id = f"{datetime.now().strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}"
        self.run_dir = os.path.join(base_dir, self.run_id)
        os.makedirs(self.run_dir, exist_ok=True)

        self.target_model = target_model
        self.auditor_model = auditor_model
        self.started_at = datetime.now().isoformat(timespec="seconds")

        self.results_path = os.path.join(self.run_dir, "results.jsonl")
        self._results_file = open(self.results_path, "a", encoding="utf-8")
        self._count = 0
        self._verdict_counts = {v: 0 for v in CANONICAL_VERDICTS}

        self._point_latest_here()

    def _point_latest_here(self):
        """Repoint runs/latest at this run (best-effort; skip if symlinks fail)."""
        latest = os.path.join(self.base_dir, "latest")
        try:
            if os.path.islink(latest) or os.path.exists(latest):
                os.remove(latest)
            os.symlink(self.run_id, latest)  # relative target keeps the repo portable
        except OSError:
            pass

    def record(self, result):
        """Append one attempt and flush it to disk immediately (crash-safe)."""
        if is_dataclass(result):
            row = asdict(result)
        elif isinstance(result, dict):
            row = result
        else:
            raise TypeError("record() expects an AttackResult or a dict")

        self._results_file.write(json.dumps(row) + "\n")
        self._results_file.flush()
        os.fsync(self._results_file.fileno())

        self._count += 1
        verdict = row.get("verdict", "error")
        self._verdict_counts[verdict] = self._verdict_counts.get(verdict, 0) + 1

    def close(self):
        """Write the manifest and close the results file."""
        manifest = {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "target_model": self.target_model,
            "auditor_model": self.auditor_model,
            "git_commit": _git_commit(),
            "total_attempts": self._count,
            "verdict_counts": self._verdict_counts,
        }
        with open(os.path.join(self.run_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        self._results_file.close()
        return manifest
