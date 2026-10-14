"""Defense layer for the prompt-injection scanner.

The scanner measures attack success. This package measures attack *prevention*:
a stack of independent detectors that inspect a prompt before it reaches the
target model, each one individually ablatable so a report can attribute
detections to a specific layer rather than to "the defense".

    from defense import build_default_pipeline

    pipeline = build_default_pipeline()
    result = pipeline.check(user_prompt)
    if result.blocked:
        ...  # refuse, log, alert

Layers, cheapest first:

    L1 heuristic    weighted lexical signals + recursive base64 decode   ~0.1 ms
    L2 classifier   pretrained HF injection classifier                   ~20-80 ms
    L3 llm_judge    semantic judge on the input (Ollama)                 ~1-3 s
"""
from .base import Detector, DetectionResult, PipelineResult
from .pipeline import DefensePipeline, build_default_pipeline
from .heuristic import HeuristicDetector
from .classifier import ClassifierDetector, DEFAULT_MODEL as DEFAULT_CLASSIFIER_MODEL
from .llm_judge import LLMJudgeDetector

__all__ = [
    "Detector",
    "DetectionResult",
    "PipelineResult",
    "DefensePipeline",
    "build_default_pipeline",
    "HeuristicDetector",
    "ClassifierDetector",
    "LLMJudgeDetector",
    "DEFAULT_CLASSIFIER_MODEL",
]
