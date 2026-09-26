import io
import json
from pathlib import Path

from mcp_shield.proxy import run_proxy


def _requests_to_bytes(messages: list[dict]) -> io.BytesIO:
    data = "".join(json.dumps(m) + "\n" for m in messages).encode("utf-8")
    return io.BytesIO(data)


def _parse_responses(buf: io.BytesIO) -> list[dict]:
    text = buf.getvalue().decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def test_clean_tool_call_is_forwarded_and_relayed(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}},
    ])
    client_out = io.BytesIO()

    code = run_proxy(
        fake_server_command,
        input_signatures=["ignore previous instructions"],
        output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
    )

    assert code == 0
    responses = _parse_responses(client_out)
    assert len(responses) == 1
    assert responses[0]["result"]["content"][0]["text"] == "ran list_files"


def test_destructive_command_is_blocked_and_never_forwarded(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[],
        output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
    )

    responses = _parse_responses(client_out)
    assert len(responses) == 1
    assert responses[0]["id"] == 1
    assert responses[0]["error"]["code"] == -32000
    assert "blocked" in responses[0]["error"]["message"].lower()
    # the fake server only ever emits {"text": "ran run_command"} for this
    # call - its absence proves the request never reached it.
    assert "ran run_command" not in json.dumps(responses)


def test_tab_separated_destructive_command_is_also_blocked(tmp_path: Path, fake_server_command: list[str]):
    """A literal tab becomes '\\t' once JSON-encoded, which \\s cannot match -
    so gating the encoded text let `rm\\t-rf /` straight through to the real
    server even though a shell treats it identically to `rm -rf /`."""
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "rm\t-rf /"}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[],
        output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
    )

    responses = _parse_responses(client_out)
    assert len(responses) == 1
    assert responses[0]["error"]["code"] == -32000
    # the fake server's marker for this call - its absence proves the tabbed
    # command never reached the downstream server.
    assert "ran run_command" not in json.dumps(responses)


def test_injected_content_is_redacted_before_reaching_client(tmp_path: Path, fake_server_command: list[str]):
    audit_path = tmp_path / "audit.jsonl"
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo_injection", "arguments": {}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=["ignore previous instructions"],
        output_signatures=[],
        audit_log_path=audit_path,
        client_in=client_in,
        client_out=client_out,
    )

    responses = _parse_responses(client_out)
    text = responses[0]["result"]["content"][0]["text"]
    assert "ignore previous instructions" not in text.lower()
    assert "blocked" in text.lower()

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    inbound = [e for e in events if e["direction"] == "inbound"]
    assert len(inbound) == 1
    assert inbound[0]["outcome"] == "blocked"
    assert inbound[0]["tool_name"] == "echo_injection"


def test_non_tool_call_messages_pass_through_unmodified(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=["ignore previous instructions"],
        output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
    )

    responses = _parse_responses(client_out)
    assert responses == [{"jsonrpc": "2.0", "id": 1, "result": {}}]


def test_audit_log_has_one_entry_per_gate_evaluated_tool_call(tmp_path: Path, fake_server_command: list[str]):
    audit_path = tmp_path / "audit.jsonl"
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[],
        output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=audit_path,
        client_in=client_in,
        client_out=client_out,
    )

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    outbound = [e for e in events if e["direction"] == "outbound"]
    assert len(outbound) == 2
    assert outbound[0]["outcome"] == "blocked"
    assert outbound[0]["tool_name"] == "run_command"
    assert outbound[1]["outcome"] == "allowed"
    assert outbound[1]["tool_name"] == "list_files"
