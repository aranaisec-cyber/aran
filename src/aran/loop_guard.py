"""Detects a tool being called identically, repeatedly, in a short window -
a stuck or looping agent hammering the same call. None of the signature
gates can catch this: a single `list_files` call, or even a single retry
of a flaky network call, looks completely benign on its own. It's the
*pattern* - the same call, many times, fast - that's the signal, not any
one call's content.

Opt-in (ARAN_LOOP_GUARD=1, off by default) because it's the one gate in
this project based on frequency/timing rather than content: a legitimate,
fast, repeated call (polling, intentional retries) is a real pattern this
can't distinguish from a genuine stuck loop by design, and getting that
wrong blocks something that was never dangerous. Everything else in Aran
is opt-out (protection is on unless you go out of your way to disable a
specific check); this one flips that, the same way the GitHub repo scan
does for a different reason (making network calls).
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from typing import Any

DEFAULT_THRESHOLD = 20
DEFAULT_WINDOW_SECONDS = 60.0

# Bound on how many distinct (tool_name, arguments) keys are tracked at
# once - an agent legitimately calling many different tools with many
# different arguments must not grow this without limit. Evicting the
# oldest-created key under the cap costs, at worst, momentarily forgetting
# one call pattern's recent history - never a security check, the same
# "bounded, best-effort" posture pending_tool_calls already documents.
_MAX_TRACKED_KEYS = 4096


class LoopGuard:
    def __init__(self, *, threshold: int = DEFAULT_THRESHOLD, window_seconds: float = DEFAULT_WINDOW_SECONDS):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._recent: dict[str, deque[float]] = {}

    @staticmethod
    def _key(tool_name: str, arguments: Any) -> str:
        try:
            canonical = json.dumps(arguments, sort_keys=True, default=str)
        except (TypeError, ValueError):
            canonical = repr(arguments)
        # Hashed rather than stored raw: a large argument payload repeated
        # many times must not make this structure's memory usage scale
        # with payload size, only with the (bounded) number of distinct keys.
        return hashlib.sha256(f"{tool_name}:{canonical}".encode("utf-8", errors="replace")).hexdigest()

    def record(self, tool_name: str, arguments: Any) -> int:
        """Records one call and returns how many identical (same tool name,
        same arguments) calls - including this one - have happened within
        the trailing window."""
        key = self._key(tool_name, arguments)
        now = time.monotonic()
        window = self._recent.setdefault(key, deque())
        window.append(now)
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        while len(self._recent) > _MAX_TRACKED_KEYS:
            self._recent.pop(next(iter(self._recent)))
        return len(window)

    def would_block(self, count: int) -> bool:
        return count >= self.threshold
