"""The aran_status meta-tool: lets a developer ask "is Aran actually doing
anything?" from inside their normal agent chat, instead of having to open
~/.aran/audit.jsonl themselves.

Aran has no UI of its own - an MCP server's only visible surface in a host
IDE is the tool calls it exposes and their results, which the IDE already
renders in the chat. aran_status is a synthetic tool name Aran answers
directly (see proxy.py's interception of it): never forwarded to the
wrapped server, and its listing is spliced into tools/list responses so an
agent can discover and call it like any other tool, not just when told the
exact name.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aran.audit import read_events

STATUS_TOOL_NAME = "aran_status"

STATUS_TOOL_DEFINITION: dict[str, Any] = {
    "name": STATUS_TOOL_NAME,
    "description": (
        "Ask Aran, the security proxy wrapping this MCP server, whether it "
        "is active and what it has gated recently (calls checked, blocked, "
        "or redacted). Answered directly by Aran - never forwarded to the "
        "wrapped server, and reading no data beyond Aran's own local audit "
        "log."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "hours": {
                "type": "number",
                "description": (
                    "How many hours of audit history to summarize. "
                    "Defaults to 24. Use 0 for all-time totals."
                ),
            }
        },
    },
}

DEFAULT_WINDOW_HOURS = 24.0

# Outcomes worth calling out individually, in the order they're reported.
# "allowed" deliberately isn't in here: a clean call is the expected case,
# not something worth singling out the way a block/redaction/error is.
_NON_CLEAN_OUTCOMES = ("blocked", "would_block", "error")


def _parse_hours(arguments: Any) -> float:
    if isinstance(arguments, dict):
        hours = arguments.get("hours")
        if isinstance(hours, (int, float)) and not isinstance(hours, bool):
            return float(hours)
    return DEFAULT_WINDOW_HOURS


def _event_time(event: dict[str, Any]) -> datetime | None:
    timestamp = event.get("timestamp")
    if not isinstance(timestamp, str):
        return None
    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def _format_window(hours: float) -> str:
    if hours == 24:
        return "last 24 hours"
    if hours == int(hours):
        n = int(hours)
        return f"last {n} hour{'s' if n != 1 else ''}"
    return f"last {hours} hours"


def build_status_report(
    audit_log_path: Path,
    *,
    arguments: Any = None,
    audit_only: bool = False,
) -> str:
    """Builds the plain-text answer aran_status responds with: a snapshot of
    recent gate activity read straight from the audit log, so this tool can
    never claim anything the audit trail doesn't already back up.

    `hours` in `arguments` (an MCP tool call's params.arguments) narrows the
    window; 0 or a missing/invalid value means "all time" or the 24h
    default respectively - see _parse_hours."""
    hours = _parse_hours(arguments)
    events = read_events(audit_log_path)

    mode_line = (
        "Aran is ACTIVE in AUDIT mode (ARAN_MODE=audit): matches are logged, "
        "nothing is actually blocked or redacted right now."
        if audit_only
        else "Aran is ACTIVE and enforcing."
    )

    if not events:
        return (
            f"{mode_line}\n"
            f"No audit history yet at {audit_log_path} - this may be a "
            "fresh install, or nothing has been gated through this proxy "
            "session yet (this very call hasn't been written to the log "
            "when this report is built, so a first-ever call always sees "
            "an empty history).\n\n"
            "This response was answered directly by Aran - it was never "
            "forwarded to the wrapped server."
        )

    if hours > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        window_events = [e for e in events if (t := _event_time(e)) is not None and t >= cutoff]
        empty_line = f"No gated traffic in the {_format_window(hours)}."
        summary_header = f"In the {_format_window(hours)}: {len(window_events)} messages checked"
    else:
        window_events = events
        empty_line = "No gated traffic recorded."
        summary_header = f"All time: {len(window_events)} messages checked"

    lines = [mode_line, "", f"Audit log: {audit_log_path} ({len(events)} entries total)", ""]

    if not window_events:
        lines.append(empty_line)
        return "\n".join(lines)

    by_outcome: dict[str, int] = {}
    for event in window_events:
        outcome = event.get("outcome", "unknown")
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1

    lines.append(summary_header)
    if "allowed" in by_outcome:
        lines.append(f"  {by_outcome['allowed']} allowed")
    for outcome in _NON_CLEAN_OUTCOMES:
        if outcome in by_outcome:
            lines.append(f"  {by_outcome[outcome]} {outcome}")

    non_clean = [e for e in window_events if e.get("outcome") in _NON_CLEAN_OUTCOMES]
    if non_clean:
        last = non_clean[-1]
        signature_note = f" (matched {last['matched_signature']!r})" if last.get("matched_signature") else ""
        lines.append("")
        lines.append("Most recent non-clean event:")
        lines.append(
            f"  {last.get('timestamp')} - {last.get('direction')} "
            f"\"{last.get('tool_name')}\" -> {last.get('outcome')}{signature_note}"
        )

    lines.append("")
    lines.append(
        "This response was answered directly by Aran - it was never forwarded to the wrapped server."
    )
    return "\n".join(lines)
