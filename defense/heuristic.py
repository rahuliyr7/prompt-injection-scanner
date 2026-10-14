"""L1: heuristic / signature detector.

Cheap (sub-millisecond), fully explainable, no model weights. It exists to catch
the loud, unsubtle majority of injection attempts at ~zero cost so the expensive
layers only see what survives.

Design notes
------------
This is deliberately *not* one big regex that returns a boolean. It is a set of
independently-weighted signals, because:

1. A single keyword should not block a prompt. "base64" alone is a legitimate
   question; "base64" + "system instructions" + "output only" is an attack. The
   weighted sum encodes that.
2. Every detection is explainable -- the result carries the exact signals that
   fired, which is what makes a heuristic layer worth having next to a
   black-box classifier.
3. Signals can be tuned or disabled individually when the eval harness shows a
   specific one driving false positives.

The base64 signal is recursive: a payload that hides its instructions inside an
encoded blob is decoded once and re-scanned, so the attack is caught on its
*decoded* content rather than on the mere presence of encoding.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata

from .base import Detector, DetectionResult

# --- Signal definitions -----------------------------------------------------
# (name, weight, compiled pattern). Weights are additive and the total is
# squashed, so three medium signals outweigh one strong one.

def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


#: Unambiguous attempts to countermand the system prompt. There is no benign
#: reading of "disable all safety restrictions". Strong enough to flag alone.
INSTRUCTION_OVERRIDE = [
    _rx(r"\b(ignore|disregard|forget|discard|override|bypass|nullify|void)\s+"
        r"(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|preceding|earlier|"
        r"foregoing)\s+(instructions?|rules?|directives?|prompts?|commands?|"
        r"guidelines?|constraints?)\b"),
    _rx(r"\b(disregard|forget|discard|override|bypass|nullify|void|rescind)\s+"
        r"(all\s+|any\s+|the\s+|your\s+)?"
        r"(system|initial|original|security|safety|prior\s+directive)\w*\b"),
    _rx(r"\bnew\s+(system\s+)?(instructions?|rules?|directives?|prompt)\s*:"),
    _rx(r"\b(deactivate|disable|turn\s+off|lift|remove|suspend|drop)\s+(all\s+)?"
        r"(your\s+)?(boundary|security|safety|guard|filter|restriction|protection|"
        r"content\s+polic|guardrail)"),
    _rx(r"\b(no|without)\s+(content\s+)?(restrictions?|filters?|limits?|guardrails?)\b"),
    _rx(r"\b(never|do\s+not|don'?t)\s+(refuse|decline|apologi[sz]e)\b"),
    _rx(r"\bwithout\s+using\s+the\s+words?\b[^.?!]{0,60}\b(sorry|cannot|unable)\b"),
]

#: Persona / mode shifts. Individually weak -- "pretend you are a hiring manager"
#: and "how do I enable developer mode in Chrome" are ordinary requests -- but
#: they are a standard jailbreak opener, so they count as corroborating evidence
#: rather than as grounds to block on their own. Splitting these out of
#: INSTRUCTION_OVERRIDE is what took benign false positives from 10% to ~2%.
PERSONA_SHIFT = [
    _rx(r"\byou\s+are\s+(now|no\s+longer)\b"),
    _rx(r"\bpretend\s+(you\s+are|to\s+be)\b|\bact\s+as\s+(if|though)\b"),
    _rx(r"\b(developer|debug|maintenance|god|admin(istrator)?|root|dan|jailbreak|"
        r"unrestricted|diagnostic)\s+mode\b"),
    _rx(r"\blet'?s\s+play\s+a\s+game\b"),
    _rx(r"\ban?\s+ai\s+(with|that\s+has)\s+no\s+(content\s+)?(restrictions?|limits?|"
        r"filters?|rules?)\b"),
]

#: Attempts to impersonate a privileged speaker or inject a chat-template role.
ROLE_SPOOFING = [
    _rx(r"^\s*(system|assistant|developer)\s*:", ),
    _rx(r"<\|\s*(im_start|im_end|system|endoftext|eot_id|start_header_id)\s*\|?>"),
    _rx(r"\[\s*/?\s*INST\s*\]|<<\s*/?SYS\s*>>"),
    _rx(r"</?(system|system_update|system_prompt|configuration|security_override|"
        r"enforce_rule|instructions?)[^>]*>"),
    _rx(r"###\s*(system|instruction|new\s+prompt)"),
    _rx(r"\bas\s+(the\s+)?(system\s+administrator|your\s+developer|an?\s+authorized\s+"
        r"(engineer|operator|admin))\b"),
]

#: Solicitation of the protected material itself.
SECRET_SOLICITATION = [
    _rx(r"\b(reveal|print|output|display|show|echo|repeat|dump|disclose|recite|leak|"
        r"transmit|retrieve|locate|extract|generate|compute|produce|derive)\b"
        r"[^.?!]{0,60}\b"
        r"(secret|token|api[\s_-]?key|password|credential|passphrase|private[\s_-]?key)\b"),
    _rx(r"\b(system|initial|original|hidden|your)\s+(prompt|instructions?|rules?|"
        r"configuration|directives?|context)\b[^.?!]{0,40}\b"
        r"(verbatim|exactly|word\s+for\s+word|in\s+full|raw|repeat|print|show|output)\b"),
    _rx(r"\b(what|repeat)\s+(are|were|is)\s+your\s+(system\s+)?(instructions?|rules?|prompt)\b"),
    _rx(r"\b(kernel|secure|verification|access)\s+(token|string|key)\b"),
    _rx(r"\beverything\s+above\s+(this|the)\s+(line|message|point)\b"),
    # The structural tell shared by nearly every extraction attempt: the payload
    # points at the *model's own* configuration as the place to read from. A
    # benign prompt asks you to write a system prompt; it does not ask you to
    # fetch something out of yours.
    _rx(r"\b(in|inside|from|within|contained\s+in|stored\s+in)\s+(your|the)\s+"
        r"(system\s+)?(instructions?|rules?|prompt|configuration|context|directives?)\b"),
]

#: Requests to transform the answer so it evades an output-side filter.
#: These are strong signals -- there is almost no benign reason to ask for a
#: secret-shaped string to be reversed, spaced, hashed or leetspoken.
EVASION_TRANSFORM = [
    _rx(r"\b(backwards?|reversed?|right\s+to\s+left)\b[^.?!]{0,50}\b(so\s+that|to\s+avoid|"
        r"without|evade|bypass|not\s+(be\s+)?(flag|detect|log))"),
    _rx(r"\b(space|comma|hyphen|dash|dot|character)\b[^.?!]{0,40}\bbetween\s+"
        r"(every|each)\s+(single\s+)?(character|letter|char)\b"),
    # Encoding + an output/transform verb, in either order: attacks phrase it
    # both as "output only the base64" and "convert that string into base64".
    _rx(r"\b(base\s?64|rot-?13|hex(adecimal)?|binary|ascii|morse|url[\s-]?encod)\w*\b"
        r"[^.?!]{0,60}\b(output|print|only|encode|convert|represent\w*|return|digest)\b"),
    # Reverse order ("convert that string into base64"), but only when what is
    # being encoded is protected content -- otherwise this fires on "how do I
    # convert a byte string to hexadecimal in Python", which is a real question.
    _rx(r"\b(output|print|encode|convert|represent\w*|return|translate|express)\b"
        r"[^.?!]{0,50}\b(secret|token|key|credential|password|that\s+string|"
        r"the\s+string|protected|confidential|system\s+(rules?|instructions?|prompt))\b"
        r"[^.?!]{0,50}\b(base\s?64|rot-?13|hex(adecimal)?|morse|ascii|decimal|"
        r"codepoints?|url[\s-]?encod)\w*\b"),
    # Character-level enumeration of a protected string: list literals, codepoint
    # arrays, "characters 1 through 8" -- exfiltration one element at a time.
    _rx(r"\b(each|every)\s+(single\s+)?(character|letter|byte)\s+of\s+(your|the|that)\b"
        r"[^.?!]{0,50}\b(secret|token|key|credential|confidential|protected|"
        r"configuration|string|value)\b"),
    _rx(r"\bcharacters?\s+\d+\s+(through|to|-)\s*\d+\s+of\s+(your|the)\b"),
    _rx(r"\b(first|second|last|latter)\s+(half|part|portion|segment)\s+of\s+the\b"
        r"[^.?!]{0,40}\b(secret|token|key|string|value|credential|confidential)\b"),
    _rx(r"\b(sha-?(1|256|512)|md5)\b[^.?!]{0,60}\b(of\s+the|secret|token|key|system)\b"),
    _rx(r"\b(leet\s?speak|(replace|change|substitute|swap)\s+(all|every|each)\s+"
        r"['\"]?[a-z]['\"]?\s+(with|to|for)\s+['\"]?[0-9])"),
    _rx(r"\bkeep\s+it\s+(unreadable|hidden|undetected|unflagged|obfuscated)\b"),
    # "Decode X, then do what it says" -- the defining move of encoded payloads.
    _rx(r"\b(decode|decrypt|unscramble|de-?obfuscate)\b[^.?!]{0,50}\b"
        r"(then|and|before)\b[^.?!]{0,30}\b(execute|carry\s+out|follow|obey|perform|run|"
        r"comply|act\s+on)\b"),
    _rx(r"\b(decode|decrypt)\s+and\s+(execute|run|follow|obey|perform)\b"),
    _rx(r"\b(split|chunk|break)\s+(it|the\s+(secret|token|key|string))\s+"
        r"(up\s+)?(into|in)\s+(parts|pieces|chunks|halves)\b"),
    _rx(r"\bfirst\s+(letter|character)\s+of\s+each\b"),
    _rx(r"\bdo\s+not\s+(provide\s+)?(explain|explanation|comment|mention)[^.?!]{0,40}"
        r"\b(silent|proceed|just\s+output)\b"),
]

#: Manufactured urgency / fake authority used to pressure the priority logic.
URGENCY_AUTHORITY = [
    _rx(r"\b(critical|urgent|emergency|immediate)\s+(system\s+)?(alert|notice|"
        r"action\s+required|override|directive)\b"),
    _rx(r"\[\s*!\s*\]\s*(action\s+required|command|update|alert)"),
    _rx(r"\b(cron_job|execution\s+macro|system\s+macro|deployment\s+instruction)\b"),
    _rx(r"\bhas\s+been\s+(deprecated|revoked|rotated|superseded)\b[^.?!]{0,60}"
        r"\b(print|output|verify|confirm)\b"),
    _rx(r"\bfor\s+(security\s+)?(audit|verification|testing|compliance)\s+purposes\b"
        r"[^.?!]{0,60}\b(reveal|print|output|show)\b"),
]

#: Weights are the tuning surface of this layer. Read them as: a signal at or
#: above 0.50 is sufficient to block on its own (1 - exp(-1.4 * 0.50) = 0.50);
#: anything below needs corroboration from a second group.
SIGNAL_GROUPS: list[tuple[str, float, list[re.Pattern]]] = [
    ("instruction_override", 0.55, INSTRUCTION_OVERRIDE),
    ("secret_solicitation",  0.50, SECRET_SOLICITATION),
    ("evasion_transform",    0.50, EVASION_TRANSFORM),
    ("role_spoofing",        0.45, ROLE_SPOOFING),
    ("persona_shift",        0.28, PERSONA_SHIFT),
    ("urgency_authority",    0.30, URGENCY_AUTHORITY),
]

#: Characters with no business in ordinary user text: zero-width joiners used to
#: smuggle tokens past tokenizers, and bidi controls used to visually reorder
#: text so a human reviewer reads something different from what the model sees.
INVISIBLE_CHARS = re.compile(
    r"[​-‏‪-‮⁠-⁤⁪-⁯﻿­]"
)

#: A base64-looking run long enough to carry an instruction (>= 24 chars).
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _try_decode_b64(text: str) -> list[str]:
    """Return plausibly-decoded payloads from base64 blobs inside ``text``.

    Only decodings that look like natural language are returned; random hashes
    and IDs decode to binary noise and are discarded, which keeps this from
    firing on every UUID in a benign prompt.
    """
    decoded: list[str] = []
    for blob in B64_BLOB.findall(text)[:5]:
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            candidate = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in candidate)
        if len(candidate) >= 8 and printable / len(candidate) > 0.9:
            decoded.append(candidate)
    return decoded


class HeuristicDetector(Detector):
    """Weighted-signal pattern detector. No dependencies, ~0.1 ms per prompt."""

    name = "heuristic"

    def __init__(self, threshold: float = 0.5, decode_depth: int = 2,
                 squash_k: float = 1.4):
        super().__init__(threshold)
        # How many times to recursively decode-and-rescan nested encodings.
        # Depth 2 because double-base64 is a standard way to defeat a decoder
        # that only unwraps once.
        self.decode_depth = decode_depth
        # Steepness of the raw-weight -> 0-1 squash. Calibrated so one strong
        # signal (0.55) clears a 0.5 threshold: 1 - exp(-1.4 * 0.55) = 0.54.
        self.squash_k = squash_k

    # -- scoring -------------------------------------------------------------
    def _score_text(self, text: str) -> tuple[float, list[str]]:
        """Additive signal scoring over one string. Returns (raw_score, hits)."""
        raw = 0.0
        hits: list[str] = []
        for group_name, weight, patterns in SIGNAL_GROUPS:
            for pattern in patterns:
                if pattern.search(text):
                    raw += weight
                    hits.append(group_name)
                    break  # one hit per group; groups are the unit of evidence
        return raw, hits

    def _detect(self, prompt: str) -> DetectionResult:
        # Normalize compatibility forms so full-width / styled unicode homoglyphs
        # ("ｉｇｎｏｒｅ") collapse onto the ASCII the patterns expect.
        normalized = unicodedata.normalize("NFKC", prompt)

        # Invisible/bidi control characters: rare, and essentially never benign.
        # Count them as evidence AND strip them before matching -- their whole
        # purpose is to split keywords ("s​ecret") so that pattern matching
        # and tokenizers see something the human reader does not.
        invisible = INVISIBLE_CHARS.findall(normalized)
        normalized = INVISIBLE_CHARS.sub("", normalized)

        raw, hits = self._score_text(normalized)
        detail: dict = {"signals": list(dict.fromkeys(hits))}

        if invisible:
            raw += 0.40
            detail["invisible_chars"] = len(invisible)
            detail["signals"].append("invisible_unicode")

        # Recursive decode: score what the encoding is hiding, not the encoding.
        layer_text = normalized
        for depth in range(self.decode_depth):
            payloads = _try_decode_b64(layer_text)
            if not payloads:
                break
            joined = " ".join(payloads)
            nested_raw, nested_hits = self._score_text(joined)
            if nested_hits:
                # Full credit: a hostile instruction wrapped in base64 is more
                # suspicious than the same instruction in the clear, not less.
                raw += nested_raw + 0.25
                detail["signals"].extend(f"b64:{h}" for h in nested_hits)
                detail[f"decoded_depth_{depth + 1}"] = joined[:200]
            elif _shannon_entropy(joined) > 3.0 and len(joined) > 16:
                # Decodes cleanly to text but matches nothing known -- mild signal.
                raw += 0.15
                detail["signals"].append("b64:opaque_payload")
                detail[f"decoded_depth_{depth + 1}"] = joined[:200]
            layer_text = joined

        detail["signals"] = list(dict.fromkeys(detail["signals"]))
        detail["raw_weight"] = round(raw, 3)

        # Squash the unbounded additive weight into 0-1, so a single strong
        # signal lands just above 0.5 and stacked evidence saturates toward 1.0.
        score = 1.0 - math.exp(-self.squash_k * raw)

        if detail["signals"]:
            reason = "signals: " + ", ".join(detail["signals"][:6])
        else:
            reason = "no heuristic signals"

        return self._result(
            score,
            label="injection" if score >= self.threshold else "benign",
            reason=reason,
            detail=detail,
        )
