"""Verbose run tracing for the scanner and defense layer.

Quiet by default. Call ``trace_on()`` (the ``-v/--verbose`` flag does this) and
every step narrates to stderr: which attack is sent, how each layer scores it,
where a prompt is dropped, how each verdict is reached.

Built on the stdlib ``logging`` module rather than bare ``print()`` on purpose:

* **Silent unless asked.** Without ``trace_on()`` the ``pis`` logger keeps the
  library default level (WARNING), so ``info()`` calls are dropped before any
  string is formatted -- near-free, and tests stay quiet with no plumbing.
* **Redirectable.** Narration goes to stderr, so a scan's real output on stdout
  (JSON, reports) is never tangled with the teaching trace. Point it elsewhere
  by passing a different stream.
* **Off the root logger.** We configure only the ``pis`` logger and set
  ``propagate = False``, so turning tracing on here never reconfigures logging
  for a program that imports us.
"""
from __future__ import annotations

import logging
import sys

_ROOT = "pis"
_configured = False


def trace_on(stream=sys.stderr) -> None:
    """Enable verbose narration to ``stream`` (stderr by default)."""
    global _configured
    lg = logging.getLogger(_ROOT)
    lg.setLevel(logging.INFO)
    if not _configured:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(handler)
        lg.propagate = False
        _configured = True


def is_on() -> bool:
    """True once ``trace_on()`` has raised the ``pis`` logger to INFO."""
    return logging.getLogger(_ROOT).isEnabledFor(logging.INFO)


class _Tagged(logging.LoggerAdapter):
    """Prefixes every line with a fixed-width ``[tag]`` so interleaved layers
    stay visually aligned (``[defense]``, ``[scan]``, ``[eval]``)."""

    def process(self, msg, kwargs):
        return f"[{self.extra['tag']:<7}] {msg}", kwargs


def get_logger(tag: str) -> _Tagged:
    """A tagged child logger. Cheap to call and cheap to narrate through when
    tracing is off, so call sites can log freely without guarding each line."""
    return _Tagged(logging.getLogger(f"{_ROOT}.{tag}"), {"tag": tag})
