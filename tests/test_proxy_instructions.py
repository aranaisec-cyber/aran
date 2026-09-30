import io
import json
from pathlib import Path

from aran.proxy import run_proxy
from aran.status import PROXY_INSTRUCTIONS


def _requests_to_bytes(messages: list[dict]) -> io.BytesIO:
    data = "".join(json.dumps(m) + "\n" for m in messages).encode("utf-8")
    return io.BytesIO(data)


def _parse_responses(buf: io.BytesIO) -> list[dict]:
    text = buf.getvalue().decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def test_initialize_response_gets_proxy_instructions_appended(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
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
    assert responses[0]["result"]["instructions"].endswith(PROXY_INSTRUCTIONS)


def test_initialize_instructions_are_appended_not_replaced(tmp_path: Path, fake_server_command: list[str]):
    """fake_server.py's initialize result carries its own instructions
    field ("Use this server for pages.") - proves Aran appends
    PROXY_INSTRUCTIONS to it rather than clobbering content the agent
    still needs."""
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
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
    instructions = responses[0]["result"]["instructions"]
    assert instructions.startswith("Use this server for pages.")
    assert PROXY_INSTRUCTIONS in instructions


def test_a_non_initialize_response_is_not_touched(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}},
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
    assert "instructions" not in json.dumps(responses)


def test_initialize_in_audit_only_mode_still_gets_instructions(tmp_path: Path, fake_server_command: list[str]):
    """The splice is not a gating decision, so ARAN_MODE=audit must not
    disable it - the agent should learn what -32001/-32002 mean regardless
    of whether Aran is currently enforcing or just observing."""
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
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
    assert responses[0]["result"]["instructions"].endswith(PROXY_INSTRUCTIONS)
