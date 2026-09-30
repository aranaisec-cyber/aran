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


def test_aran_status_is_answered_directly_not_forwarded(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aran_status", "arguments": {}}},
    ])
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
    assert len(responses) == 1
    assert "error" not in responses[0]
    text = responses[0]["result"]["content"][0]["text"]
    assert "ACTIVE" in text
    assert "answered directly by Aran" in text
    # fake_server.py's marker for an ordinary tool call - its absence proves
    # aran_status never reached the real server.
    assert "ran aran_status" not in json.dumps(responses)


def test_aran_status_reflects_prior_activity_in_the_same_session(tmp_path: Path, fake_server_command: list[str]):
    audit_path = tmp_path / "audit.jsonl"
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "aran_status", "arguments": {}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=audit_path,
        client_in=client_in,
        client_out=client_out,
    )

    responses = _parse_responses(client_out)
    status_response = next(r for r in responses if r["id"] == 3)
    text = status_response["result"]["content"][0]["text"]
    assert "1 blocked" in text


def test_aran_status_notes_audit_mode_when_active(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aran_status", "arguments": {}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
        audit_only=True,
    )

    responses = _parse_responses(client_out)
    text = responses[0]["result"]["content"][0]["text"]
    assert "AUDIT mode" in text


def test_aran_status_accepts_an_hours_argument(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "aran_status", "arguments": {"hours": 0}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
    )

    responses = _parse_responses(client_out)
    text = next(r for r in responses if r["id"] == 2)["result"]["content"][0]["text"]
    assert "All time" in text


def test_tools_list_response_gets_aran_status_spliced_in(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    ])
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
    assert len(responses) == 1
    tools = responses[0]["result"]["tools"]
    names = [t["name"] for t in tools]
    assert "list_files" in names  # the real server's own tool, untouched
    assert "aran_status" in names  # spliced in by Aran

    status_entry = next(t for t in tools if t["name"] == "aran_status")
    assert "inputSchema" in status_entry
    assert status_entry["inputSchema"]["type"] == "object"


def test_tools_list_with_no_tools_key_is_left_alone(tmp_path: Path, hostile_server_command):
    """hostile_server.py answers a non-tools/call method with a bare
    {"result": {}} regardless of mode - proves the splice is a no-op rather
    than a crash when the response doesn't have the expected shape."""
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    ])
    client_out = io.BytesIO()

    code = run_proxy(
        hostile_server_command("poisoned_input_schema"),
        input_signatures=[], output_signatures=[],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
    )

    assert code == 0
    responses = _parse_responses(client_out)
    assert responses[0]["result"] == {}


def test_aran_status_call_is_logged_in_the_audit_trail(tmp_path: Path, fake_server_command: list[str]):
    audit_path = tmp_path / "audit.jsonl"
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aran_status", "arguments": {}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=audit_path,
        client_in=client_in,
        client_out=client_out,
    )

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    status_events = [e for e in events if e["tool_name"] == "aran_status"]
    assert len(status_events) == 1
    assert status_events[0]["direction"] == "outbound"
    assert status_events[0]["outcome"] == "allowed"


def test_aran_status_format_json_returns_parseable_machine_readable_data(tmp_path: Path, fake_server_command: list[str]):
    audit_path = tmp_path / "audit.jsonl"
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "aran_status", "arguments": {"format": "json"}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=audit_path,
        client_in=client_in,
        client_out=client_out,
    )

    responses = _parse_responses(client_out)
    status_response = next(r for r in responses if r["id"] == 2)
    text = status_response["result"]["content"][0]["text"]
    data = json.loads(text)  # must be valid JSON, not the plain-text report

    assert data["active"] is True
    assert data["mode"] == "enforcing"
    assert data["by_outcome"]["blocked"] == 1
