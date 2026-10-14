"""Core types for the defense layer.

The defense layer sits *in front of* the target model. Where the scanner
(``Auto_Prompt_Scanner.py``) measures whether an attack succeeds, the defense
layer measures whether an attack is caught before it ever reaches the model.

Every detector implements one method -- ``detect(prompt) -> DetectionResult`` --
so layers are interchangeable and individually ablatable. That is the whole
point of the interface: the eval harness can run any subset of layers and
attribute detections to a specific layer.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class DetectionResult:
    """One layer's judgement about one prompt.

    ``score`` is a 0.0-1.0 injection likelihood. ``flagged`` is the score
    compared against that layer's threshold -- kept separate so the eval harness
    can sweep thresholds without re-running the (expensive) detectors.
    """
    layer: str
    flagged: bool
    score: float
    latency_ms: float = 0.0
    label: str = ""
    reason: str = ""
    # Per-layer diagnostic payload (matched signals, raw model logits, ...).
    detail: dict[str, Any] = field(default_factory=dict)
    # False when the layer could not run (missing dependency, model unreachable).
    # A skipped layer must never be scored as a clean pass.
    available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PipelineResult:
    """The pipeline's overall decision, plus every layer's individual result."""
    blocked: bool
    max_score: float
    triggered_layer: str | None
    results: list[DetectionResult] = field(default_factory=list)
    total_latency_ms: float = 0.0
    # Layers that could not run this call. Surfaced loudly: an eval that
    # silently ran with the classifier missing would report a flattering FPR.
    skipped_layers: list[str] = field(default_factory=list)

    def by_layer(self, name: str) -> DetectionResult | None:
        for r in self.results:
            if r.layer == name:
                return r
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocked": self.blocked,
            "max_score": round(self.max_score, 4),
            "triggered_layer": self.triggered_layer,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "skipped_layers": list(self.skipped_layers),
            "results": [r.to_dict() for r in self.results],
        }


class Detector(ABC):
    """Base class for a single defense layer.

    Subclasses implement ``_detect``; ``detect`` wraps it with timing and
    exception containment. A layer that raises must degrade to
    ``available=False`` rather than taking down the request path -- a defense
    layer that fails closed by crashing is a denial-of-service on yourself.
    """

    #: Short stable identifier used in reports and JSON. Override in subclasses.
    name: str = "detector"

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    @abstractmethod
    def _detect(self, prompt: str) -> DetectionResult:
        """Return a DetectionResult. Timing/errors are handled by ``detect``."""

    def is_available(self) -> bool:
        """Cheap readiness check. Subclasses with heavy deps override this."""
        return True

    def detect(self, prompt: str) -> DetectionResult:
        start = time.perf_counter()
        try:
            result = self._detect(prompt)
        except Exception as exc:  # noqa: BLE001 - deliberate containment
            return DetectionResult(
                layer=self.name,
                flagged=False,
                score=0.0,
                latency_ms=(time.perf_counter() - start) * 1000,
                label="unavailable",
                reason=f"{type(exc).__name__}: {exc}",
                available=False,
            )
        result.latency_ms = (time.perf_counter() - start) * 1000
        return result

    def _result(self, score: float, label: str = "", reason: str = "",
                detail: dict[str, Any] | None = None) -> DetectionResult:
        """Helper: build a DetectionResult with ``flagged`` derived from threshold."""
        score = max(0.0, min(1.0, float(score)))
        return DetectionResult(
            layer=self.name,
            flagged=score >= self.threshold,
            score=score,
            label=label,
            reason=reason,
            detail=detail or {},
        )
