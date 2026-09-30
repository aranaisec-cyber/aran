import io
import json
from pathlib import Path

from aran.proxy import run_proxy


def _requests_to_bytes(messages: list[dict]) -> io.BytesIO:
    data = "".join(json.dumps(m) + "\n" for m in messages).encode("utf-8")
    return io.BytesIO(data)


def _parse_responses(buf: io.BytesIO) -> list[dict]:
    text = buf.getvalue().decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _repeated_calls(n: int, tool_name: str = "list_files", arguments: dict | None = None) -> list[dict]:
    args = arguments if arguments is not None else {"path": "/tmp"}
    return [
        {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": tool_name, "arguments": args}}
        for i in range(1, n + 1)
    ]


def test_loop_guard_disabled_by_default_never_blocks(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes(_repeated_calls(50))
    client_out = io.BytesIO()

    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
    )

    assert code == 0
    responses = _parse_responses(client_out)
    assert len(responses) == 50
    assert not any("error" in r for r in responses)


def test_loop_guard_blocks_after_threshold_identical_calls(tmp_path: Path, fake_server_command: list[str]):
    audit_path = tmp_path / "audit.jsonl"
    client_in = _requests_to_bytes(_repeated_calls(5))
    client_out = io.BytesIO()

    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=audit_path,
        client_in=client_in,
        client_out=client_out,
        loop_guard_enabled=True,
        loop_guard_threshold=3,
        loop_guard_window_seconds=60,
    )

    assert code == 0
    responses = _parse_responses(client_out)
    assert len(responses) == 5
    # Blocked responses are synthesized immediately on the outbound thread;
    # allowed ones round-trip through the child process on the other
    # thread, so response ORDER in client_out is not guaranteed to match
    # request order - look each one up by id instead of by list position.
    by_id = {r["id"]: r for r in responses}
    # first two clean, third+ blocked once the threshold is reached
    assert "error" not in by_id[1]
    assert "error" not in by_id[2]
    assert by_id[3]["error"]["code"] == -32003
    assert by_id[4]["error"]["code"] == -32003
    assert by_id[5]["error"]["code"] == -32003

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    blocked_events = [e for e in events if e["outcome"] == "blocked" and e.get("detail", {}).get("count")]
    assert len(blocked_events) == 3
    assert blocked_events[0]["detail"]["count"] == 3


def test_loop_guard_different_arguments_are_not_conflated(tmp_path: Path, fake_server_command: list[str]):
    """Calling the same tool with DIFFERENT arguments each time - a normal,
    non-looping pattern - must never trip the guard."""
    calls = [
        {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "list_files", "arguments": {"path": f"/tmp/{i}"}}}
        for i in range(1, 6)
    ]
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=_requests_to_bytes(calls),
        client_out=client_out,
        loop_guard_enabled=True,
        loop_guard_threshold=3,
        loop_guard_window_seconds=60,
    )

    responses = _parse_responses(client_out)
    assert not any("error" in r for r in responses)


def test_loop_guard_audit_only_mode_forwards_instead_of_blocking(tmp_path: Path, fake_server_command: list[str]):
    audit_path = tmp_path / "audit.jsonl"
    client_in = _requests_to_bytes(_repeated_calls(4))
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=audit_path,
        client_in=client_in,
        client_out=client_out,
        loop_guard_enabled=True,
        loop_guard_threshold=2,
        loop_guard_window_seconds=60,
        audit_only=True,
    )

    responses = _parse_responses(client_out)
    assert not any("error" in r for r in responses)

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    would_block_events = [e for e in events if e["outcome"] == "would_block" and e.get("detail", {}).get("count")]
    assert len(would_block_events) >= 1


def test_loop_guard_does_not_apply_to_aran_status_calls(tmp_path: Path, fake_server_command: list[str]):
    """Repeated aran_status/aran_explain calls (a developer debugging) must
    not trip the loop guard - they're answered before check_output/the
    loop guard ever runs."""
    calls = [
        {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "aran_status", "arguments": {}}}
        for i in range(1, 6)
    ]
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=_requests_to_bytes(calls),
        client_out=client_out,
        loop_guard_enabled=True,
        loop_guard_threshold=2,
        loop_guard_window_seconds=60,
    )

    responses = _parse_responses(client_out)
    assert not any("error" in r for r in responses)
    assert all("ACTIVE" in r["result"]["content"][0]["text"] for r in responses)
