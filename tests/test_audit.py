import json
from pathlib import Path

from mcp_shield.audit import log_event


def test_log_event_appends_one_json_line_per_call(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"

    log_event(log_path, direction="outbound", tool_name="run_command", outcome="blocked", matched_signature=r"rm\s+-rf")
    log_event(log_path, direction="outbound", tool_name="list_files", outcome="allowed", matched_signature=None)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    first = json.loads(lines[0])
    assert first["direction"] == "outbound"
    assert first["tool_name"] == "run_command"
    assert first["outcome"] == "blocked"
    assert first["matched_signature"] == r"rm\s+-rf"
    assert "timestamp" in first

    second = json.loads(lines[1])
    assert second["outcome"] == "allowed"
    assert second["matched_signature"] is None


def test_log_event_creates_missing_parent_directories(tmp_path: Path):
    log_path = tmp_path / "nested" / "dir" / "audit.jsonl"

    log_event(log_path, direction="inbound", tool_name="read_file", outcome="allowed", matched_signature=None)

    assert log_path.exists()
