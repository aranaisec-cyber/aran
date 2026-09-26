from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

_write_lock = threading.Lock()


def log_event(
    log_path: Path,
    *,
    direction: str,
    tool_name: str | None,
    outcome: str,
    matched_signature: str | None,
) -> None:
    """Appends one JSON line to the audit log. direction is 'outbound' or
    'inbound'; outcome is 'allowed' or 'blocked'. Thread-safe: the proxy's
    two pump threads both call this concurrently."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "direction": direction,
        "tool_name": tool_name,
        "outcome": outcome,
        "matched_signature": matched_signature,
    }
    line = json.dumps(event) + "\n"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with _write_lock:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
