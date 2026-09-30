import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aran.status import (
    STATUS_TOOL_DEFINITION,
    STATUS_TOOL_NAME,
    build_status_report,
)


def _write_events(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def _event(outcome: str, *, direction="outbound", tool_name="run_command",
           matched_signature=None, minutes_ago: float = 0) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return {
        "timestamp": ts.isoformat(),
        "direction": direction,
        "tool_name": tool_name,
        "outcome": outcome,
        "matched_signature": matched_signature,
    }


def test_status_tool_definition_has_the_expected_shape():
    assert STATUS_TOOL_DEFINITION["name"] == STATUS_TOOL_NAME == "aran_status"
    assert "description" in STATUS_TOOL_DEFINITION
    assert STATUS_TOOL_DEFINITION["inputSchema"]["type"] == "object"


def test_build_status_report_with_no_log_file_reports_active_and_no_history(tmp_path: Path):
    report = build_status_report(tmp_path / "does-not-exist.jsonl")

    assert "ACTIVE" in report
    assert "No audit history yet" in report


def test_build_status_report_notes_audit_mode_when_active(tmp_path: Path):
    report = build_status_report(tmp_path / "does-not-exist.jsonl", audit_only=True)

    assert "AUDIT mode" in report
    assert "nothing is actually blocked" in report


def test_build_status_report_summarizes_recent_events(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    _write_events(log, [
        _event("allowed", minutes_ago=5),
        _event("allowed", minutes_ago=4),
        _event("blocked", matched_signature=r"rm\s+-[rfRF]+", minutes_ago=3),
        _event("allowed", minutes_ago=2),
    ])

    report = build_status_report(log)

    assert "4 messages checked" in report
    assert "3 allowed" in report
    assert "1 blocked" in report
    assert "Most recent non-clean event" in report
    assert "rm\\\\s+-[rfRF]+" in report or r"rm\s+-[rfRF]+" in report


def test_build_status_report_excludes_events_outside_the_default_window(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    _write_events(log, [
        _event("allowed", minutes_ago=5),
        _event("blocked", minutes_ago=60 * 48),  # 48 hours ago - outside default 24h window
    ])

    report = build_status_report(log)

    assert "1 messages checked" in report
    assert "1 allowed" in report
    assert "blocked" not in report


def test_build_status_report_hours_zero_means_all_time(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    _write_events(log, [
        _event("allowed", minutes_ago=5),
        _event("blocked", minutes_ago=60 * 48),
    ])

    report = build_status_report(log, arguments={"hours": 0})

    assert "All time" in report
    assert "2 messages checked" in report
    assert "1 blocked" in report


def test_build_status_report_custom_hours_window(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    _write_events(log, [
        _event("allowed", minutes_ago=30),   # inside a 1-hour window
        _event("allowed", minutes_ago=90),   # outside a 1-hour window
    ])

    report = build_status_report(log, arguments={"hours": 1})

    assert "last 1 hour" in report
    assert "1 messages checked" in report


def test_build_status_report_ignores_malformed_hours_argument(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    _write_events(log, [_event("allowed", minutes_ago=5)])

    # A non-numeric "hours" must not crash - falls back to the default window.
    report = build_status_report(log, arguments={"hours": "not a number"})

    assert "last 24 hours" in report


def test_build_status_report_tolerates_a_malformed_line_in_the_log(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "w", encoding="utf-8") as f:
        f.write(json.dumps(_event("allowed", minutes_ago=5)) + "\n")
        f.write("{not valid json\n")
        f.write(json.dumps(_event("blocked", minutes_ago=3)) + "\n")

    report = build_status_report(log)

    assert "2 entries total" in report
    assert "1 allowed" in report
    assert "1 blocked" in report


def test_build_status_report_no_events_in_window_but_log_has_history(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    _write_events(log, [_event("allowed", minutes_ago=60 * 48)])

    report = build_status_report(log)

    assert "No gated traffic in the last 24 hours." in report
