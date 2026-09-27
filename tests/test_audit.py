import json
from pathlib import Path

import pytest

from aran import audit
from aran.audit import log_event


@pytest.fixture(autouse=True)
def _reset_warn_once(monkeypatch):
    """The one-time warning flag is module state; reset it per test."""
    monkeypatch.setattr(audit, "_warned_about_failure", False)


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


# --- I6: a logging failure must never disable the gate ----------------------

def test_log_event_swallows_oserror_and_warns_once(tmp_path: Path, capsys):
    # A *file* where a directory is needed makes mkdir/open raise OSError.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    log_path = blocker / "audit.jsonl"

    for _ in range(5):
        log_event(
            log_path,
            direction="outbound",
            tool_name="run_command",
            outcome="blocked",
            matched_signature=r"rm\s+-rf",
        )

    err = capsys.readouterr().err
    assert err.count("[Aran] warning: could not write audit log") == 1
    assert "gating continues" in err


def test_log_event_does_not_raise_when_open_fails(tmp_path: Path, monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(audit, "open", boom, raising=False)

    log_event(
        tmp_path / "audit.jsonl",
        direction="inbound",
        tool_name="fetch",
        outcome="allowed",
        matched_signature=None,
    )

    assert "could not write audit log" in capsys.readouterr().err
