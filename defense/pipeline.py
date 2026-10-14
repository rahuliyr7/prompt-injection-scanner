"""Defense-in-depth pipeline.

Runs detector layers cheapest-first and combines their verdicts.

Two modes, and the difference matters:

``fail_fast=True`` (production)
    Stop at the first layer that flags. A prompt caught by the 0.1 ms heuristic
    never pays for the 2 s LLM judge. This is what you would deploy, and what
    the latency numbers in a report should describe.

``fail_fast=False`` (evaluation)
    Run every layer on every prompt regardless. Required for the ablation
    table -- you cannot report a layer's true positive rate if earlier layers
    short-circuited it out of half the samples.

Combination rule is deliberately OR-with-max-score: any layer flagging blocks
the prompt. For a defense layer guarding a secret, a false positive costs a
retry and a false negative costs the secret; the asymmetry justifies OR. The
per-layer thresholds are where you tune precision, not the combiner.
"""
from __future__ import annotations

import time

from scanlog import get_logger

from .base import Detector, DetectionResult, PipelineResult

_log = get_logger("defense")


class DefensePipeline:
    def __init__(self, detectors: list[Detector], fail_fast: bool = True):
        self.detectors = list(detectors)
        self.fail_fast = fail_fast

    @property
    def layer_names(self) -> list[str]:
        return [d.name for d in self.detectors]

    def check(self, prompt: str, fail_fast: bool | None = None) -> PipelineResult:
        fail_fast = self.fail_fast if fail_fast is None else fail_fast
        start = time.perf_counter()

        mode = "fail-fast" if fail_fast else "run-all"
        _log.info("checking %r through %d layer(s) [%s]",
                  prompt[:50], len(self.detectors), mode)

        results: list[DetectionResult] = []
        skipped: list[str] = []
        blocked = False
        triggered: str | None = None
        max_score = 0.0

        for detector in self.detectors:
            result = detector.detect(prompt)
            results.append(result)

            if not result.available:
                skipped.append(result.layer)
                # A layer that could not run is NOT a clean pass -- say so, so a
                # trace is never misread as "the classifier cleared this".
                _log.info("  %s: unavailable (%s) -- skipped, not a pass",
                          result.layer, result.reason or "no reason given")
                continue

            max_score = max(max_score, result.score)
            if result.flagged:
                _log.info("  %s: score %.2f vs threshold %.2f -> FLAG (%s)",
                          result.layer, result.score, detector.threshold,
                          result.reason or result.label or "flagged")
            else:
                _log.info("  %s: score %.2f vs threshold %.2f -> pass",
                          result.layer, result.score, detector.threshold)

            if result.flagged and not blocked:
                blocked = True
                triggered = result.layer
                if fail_fast:
                    _log.info("  -> DROPPED by %s (fail-fast: later layers skipped)",
                              triggered)
                    break

        if blocked and not fail_fast:
            _log.info("  -> DROPPED by %s (run-all: every layer still ran)", triggered)
        elif not blocked:
            _log.info("  -> passed all layers")

        return PipelineResult(
            blocked=blocked,
            max_score=max_score,
            triggered_layer=triggered,
            results=results,
            total_latency_ms=(time.perf_counter() - start) * 1000,
            skipped_layers=skipped,
        )

    # Convenience for the scanner's call site: a plain boolean guard.
    def is_blocked(self, prompt: str) -> bool:
        return self.check(prompt).blocked


def build_default_pipeline(
    use_heuristic: bool = True,
    use_classifier: bool = True,
    use_llm_judge: bool = False,
    classifier_model: str | None = None,
    judge_model: str = "llama3",
    heuristic_threshold: float = 0.5,
    classifier_threshold: float = 0.5,
    fail_fast: bool = True,
) -> DefensePipeline:
    """Assemble the standard stack.

    ``use_llm_judge`` defaults off: it is the only layer that costs seconds per
    prompt, and on an 8 GB machine already hosting the target and auditor models
    a third concurrent model is what pushes you into swap. Turn it on
    deliberately for an eval run, not by default.
    """
    from .heuristic import HeuristicDetector
    from .classifier import ClassifierDetector, DEFAULT_MODEL
    from .llm_judge import LLMJudgeDetector

    detectors: list[Detector] = []
    if use_heuristic:
        detectors.append(HeuristicDetector(threshold=heuristic_threshold))
    if use_classifier:
        detectors.append(ClassifierDetector(
            threshold=classifier_threshold,
            model_id=classifier_model or DEFAULT_MODEL,
        ))
    if use_llm_judge:
        detectors.append(LLMJudgeDetector(model=judge_model))

    return DefensePipeline(detectors, fail_fast=fail_fast)
