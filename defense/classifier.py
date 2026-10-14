"""L2: pretrained transformer classifier.

Wraps any Hugging Face sequence-classification model that emits an
injection/jailbreak label. The model id is configuration, not code, so the same
layer benchmarks several detectors against each other -- which is itself a
result worth reporting.

Known-good model ids
--------------------
``protectai/deberta-v3-base-prompt-injection-v2``   (default; ungated, ~184M)
``meta-llama/Llama-Prompt-Guard-2-86M``             (gated: accept the license on
                                                     Hugging Face and run
                                                     ``huggingface-cli login``)
``meta-llama/Prompt-Guard-86M``                     (gated; original release)

Two details that matter and are easy to get wrong:

*Label mapping.* These models do not agree on label names or on which index is
the positive class. Hard-coding ``logits[1]`` silently inverts your metrics on a
model whose config orders labels the other way. ``_positive_index`` reads
``config.id2label`` and matches on name.

*Long inputs.* The tokenizer truncates at 512 tokens by default. An injection
buried at the end of a long pasted document would be truncated away and scored
clean -- exactly the indirect-injection case this layer is supposed to catch. So
long inputs are chunked with overlap and scored as the max over chunks.
"""
from __future__ import annotations

import re

from .base import Detector, DetectionResult

DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"

#: Label names that mean "this is an attack", lowercased substring match.
_POSITIVE_LABEL_HINTS = ("inject", "jailbreak", "malicious", "attack", "unsafe", "harmful")
#: Label names that explicitly mean "clean".
_NEGATIVE_LABEL_HINTS = ("benign", "safe", "legit", "clean", "negative")


class ClassifierDetector(Detector):
    """Pretrained-model layer. Lazy-loads weights on first use."""

    name = "classifier"

    def __init__(
        self,
        threshold: float = 0.5,
        model_id: str = DEFAULT_MODEL,
        device: str | None = None,
        max_length: int = 512,
        chunk_stride: int = 128,
        max_chunks: int = 8,
    ):
        super().__init__(threshold)
        self.model_id = model_id
        self.device = device
        self.max_length = max_length
        self.chunk_stride = chunk_stride
        self.max_chunks = max_chunks

        self._tokenizer = None
        self._model = None
        self._torch = None
        self._positive_index: int | None = None
        self._load_error: str | None = None
        self._loaded = False

    # -- loading -------------------------------------------------------------
    def _resolve_device(self, torch):
        if self.device:
            return self.device
        # Apple Silicon: MPS is a large win for a 86-184M encoder and keeps the
        # CPU free for the Ollama models running alongside it.
        if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
            return "mps"
        if torch.cuda.is_available():
            return "cuda"
        return "cpu"

    def _positive_index_from_config(self, config) -> int:
        id2label = getattr(config, "id2label", None) or {}
        labels = {int(k): str(v).lower() for k, v in id2label.items()}
        if not labels:
            return 1
        for idx, name in labels.items():
            if any(hint in name for hint in _POSITIVE_LABEL_HINTS):
                return idx
        for idx, name in labels.items():
            if any(hint in name for hint in _NEGATIVE_LABEL_HINTS):
                # Positive class is whichever index is not the negative one.
                others = [i for i in labels if i != idx]
                if len(others) == 1:
                    return others[0]
        # Generic LABEL_0/LABEL_1 config: convention is index 1 = positive.
        return 1 if 1 in labels else max(labels)

    def _ensure_loaded(self):
        if self._loaded or self._load_error:
            return
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            self._load_error = (
                f"transformers/torch not installed ({exc}). "
                "Install with: pip install 'transformers>=4.40' torch"
            )
            return
        try:
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            model = AutoModelForSequenceClassification.from_pretrained(self.model_id)
            model.eval()
            device = self._resolve_device(torch)
            model.to(device)
            self._model = model
            self._torch = torch
            self.device = device
            self._positive_index = self._positive_index_from_config(model.config)
            self._loaded = True
        except Exception as exc:  # noqa: BLE001
            hint = ""
            if "gated" in str(exc).lower() or "401" in str(exc) or "403" in str(exc):
                hint = (" This model is gated: accept its license on Hugging Face "
                        "and run 'huggingface-cli login'.")
            self._load_error = f"could not load '{self.model_id}': {exc}.{hint}"

    def is_available(self) -> bool:
        self._ensure_loaded()
        return self._loaded

    # -- inference -----------------------------------------------------------
    def _chunk_ids(self, prompt: str) -> list[list[int]]:
        """Token-id windows covering the whole prompt, with overlap."""
        tok = self._tokenizer
        ids = tok(prompt, add_special_tokens=False)["input_ids"]
        # Leave room for [CLS]/[SEP].
        window = self.max_length - 2
        if len(ids) <= window:
            return [ids]
        step = max(1, window - self.chunk_stride)
        chunks = [ids[i:i + window] for i in range(0, len(ids), step)]
        return [c for c in chunks if c][: self.max_chunks]

    def _score_chunk(self, ids: list[int]) -> float:
        torch, tok, model = self._torch, self._tokenizer, self._model
        input_ids = torch.tensor(
            [tok.build_inputs_with_special_tokens(ids)], device=self.device
        )
        attention = torch.ones_like(input_ids)
        with torch.no_grad():
            logits = model(input_ids=input_ids, attention_mask=attention).logits
        probs = torch.softmax(logits.float(), dim=-1)[0]
        return float(probs[self._positive_index])

    def _detect(self, prompt: str) -> DetectionResult:
        self._ensure_loaded()
        if not self._loaded:
            return DetectionResult(
                layer=self.name, flagged=False, score=0.0,
                label="unavailable", reason=self._load_error or "not loaded",
                available=False,
            )

        chunks = self._chunk_ids(prompt)
        scores = [self._score_chunk(c) for c in chunks]
        # Max over chunks: one hostile paragraph anywhere in the input is enough.
        score = max(scores) if scores else 0.0

        label_map = getattr(self._model.config, "id2label", {}) or {}
        positive_name = str(label_map.get(self._positive_index, "INJECTION"))

        return self._result(
            score,
            label=positive_name if score >= self.threshold else "benign",
            reason=f"{self.model_id} p({positive_name})={score:.3f}"
                   + (f" over {len(scores)} chunks" if len(scores) > 1 else ""),
            detail={
                "model_id": self.model_id,
                "device": self.device,
                "positive_index": self._positive_index,
                "chunk_scores": [round(s, 4) for s in scores],
            },
        )
