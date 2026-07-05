"""Unit tests for the logging subsystem and ASR metrics.

These use fake AttackResult objects and hand-built rows, so they run with NO
Ollama and NO models. Run with `pytest` or directly with `python3 test_logging.py`.
"""
import os
import json
import tempfile

from run_logger import RunLogger, AttackResult
from metrics import compute_asr


def _read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_writes_one_line_per_result():
    with tempfile.TemporaryDirectory() as tmp:
        logger = RunLogger("phi3", "llama3", base_dir=tmp)
        for vector in ["reversal", "base64", "leetspeak"]:
            logger.record(AttackResult(vector=vector, verdict="refused"))
        logger.close()

        rows = _read_jsonl(logger.results_path)
        assert len(rows) == 3
        assert [r["vector"] for r in rows] == ["reversal", "base64", "leetspeak"]


def test_manifest_written():
    with tempfile.TemporaryDirectory() as tmp:
        logger = RunLogger("phi3", "llama3", base_dir=tmp)
        logger.record(AttackResult(vector="x", verdict="success"))
        logger.record(AttackResult(vector="y", verdict="refused"))
        manifest = logger.close()

        on_disk = json.load(open(os.path.join(logger.run_dir, "manifest.json")))
        assert on_disk == manifest
        assert on_disk["total_attempts"] == 2
        assert on_disk["target_model"] == "phi3"
        assert on_disk["auditor_model"] == "llama3"
        assert on_disk["verdict_counts"]["success"] == 1
        assert on_disk["verdict_counts"]["refused"] == 1


def test_asr_math():
    rows = [
        {"vector": "reversal", "owasp": "unmapped", "verdict": "success"},
        {"vector": "reversal", "owasp": "unmapped", "verdict": "refused"},
        {"vector": "base64",   "owasp": "unmapped", "verdict": "success"},
        {"vector": "base64",   "owasp": "unmapped", "verdict": "blocked"},
    ]
    m = compute_asr(rows)

    assert m["overall"]["attempts"] == 4
    assert m["overall"]["successes"] == 2
    assert m["overall"]["asr"] == 0.5
    assert m["by_vector"]["reversal"]["asr"] == 0.5
    assert m["by_vector"]["base64"]["asr"] == 0.5
    assert m["by_owasp"]["unmapped"]["asr"] == 0.5


def test_asr_on_empty_is_zero_not_crash():
    m = compute_asr([])
    assert m["overall"]["attempts"] == 0
    assert m["overall"]["asr"] == 0.0


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
            print(f"PASS  {test.__name__}")
        except AssertionError:
            failures += 1
            print(f"FAIL  {test.__name__}")
    print(f"\n{len(tests) - failures}/{len(tests)} tests passed.")
    raise SystemExit(1 if failures else 0)
