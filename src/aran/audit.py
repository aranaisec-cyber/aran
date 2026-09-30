from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_write_lock = threading.Lock()
_warned_lock = threading.Lock()
_warned_about_failure = False


def _warn_once(log_path: Path, error: Exception) -> None:
    """Prints a single warning for the whole process life. Audit writes happen
    on every gated message, so an unwritable log must not turn into thousands
    of duplicate stderr lines (which would itself break an IDE's stdio)."""
    global _warned_about_failure
    with _warned_lock:
        if _warned_about_failure:
            return
        _warned_about_failure = True
    print(
        f"[Aran] warning: could not write audit log {log_path}: {error}; "
        "gating continues without an audit trail",
        file=sys.stderr,
    )


def log_event(
    log_path: Path,
    *,
    direction: str,
    tool_name: str | None,
    outcome: str,
    matched_signature: str | None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Appends one JSON line to the audit log. direction is 'outbound' or
    'inbound'; outcome is 'allowed', 'blocked', 'error', or 'would_block'
    (ARAN_MODE=audit: a signature matched but the call/content was still
    forwarded unmodified). Thread-safe: the proxy's two pump threads both
    call this concurrently.

    `detail` is an optional extra field, used only by the GitHub repo scan
    (repo_scan.py) to carry the repo and matched file path - every other
    call site omits it, so the base five-field shape of an ordinary gate
    decision is unchanged.

    A logging failure is never allowed to propagate: it would kill the pump
    thread that called it and so disable the security gate itself. OSErrors
    are swallowed after a one-time warning."""
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "direction": direction,
        "tool_name": tool_name,
        "outcome": outcome,
        "matched_signature": matched_signature,
    }
    if detail is not None:
        event["detail"] = detail
    line = json.dumps(event) + "\n"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with _write_lock:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError as e:
        _warn_once(log_path, e)


def read_events(log_path: Path) -> list[dict[str, Any]]:
    """Reads and parses every line of the audit log, for read-only reporting
    (the aran_status meta-tool - see status.py). Returns [] if the file
    doesn't exist yet - a fresh install or a session with no gated traffic
    is not an error condition here.

    Tolerates a blank or malformed line by skipping it rather than raising:
    this file is meant to be readable while the proxy is still appending to
    it (the guide tells users to `tail -f` it directly), so a reader has to
    handle the same possibility of a line torn by a concurrent write that
    `tail` itself would. This is a diagnostic helper, not the gate - failing
    soft here costs one skipped line, never a security decision."""
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return []
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events
