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


def test_aran_explain_is_answered_directly_not_forwarded(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aran_explain", "arguments": {"text": "rm -rf /"}}},
    ])
    client_out = io.BytesIO()

    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
    )

    assert code == 0
    responses = _parse_responses(client_out)
    assert len(responses) == 1
    assert "error" not in responses[0]
    text = responses[0]["result"]["content"][0]["text"]
    assert "destructive_command" in text
    assert "dry run" in text
    # fake_server.py's marker for an ordinary tool call - its absence proves
    # aran_explain never reached the real server.
    assert "ran aran_explain" not in json.dumps(responses)


def test_aran_explain_does_not_actually_block_the_text_it_checks(tmp_path: Path, fake_server_command: list[str]):
    """Calling aran_explain with a destructive-looking string must not
    itself get blocked, logged as blocked, or affect any real gate
    decision - it's a dry run against the signature sets, not a real call."""
    audit_path = tmp_path / "audit.jsonl"
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aran_explain", "arguments": {"text": "rm -rf /"}}},
    ])
    client_out = io.BytesIO()

    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=audit_path,
        client_in=client_in,
        client_out=client_out,
    )

    assert code == 0
    responses = _parse_responses(client_out)
    assert "error" not in responses[0]

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 1
    assert events[0]["tool_name"] == "aran_explain"
    assert events[0]["outcome"] == "allowed"


def test_aran_explain_reports_clean_text_matches_nothing(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aran_explain", "arguments": {"text": "list my files"}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=["ignore previous instructions"], output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
    )

    responses = _parse_responses(client_out)
    text = responses[0]["result"]["content"][0]["text"]
    assert "No signature matches" in text


def test_tools_list_response_gets_both_meta_tools_spliced_in(tmp_path: Path, fake_server_command: list[str]):
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
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
    names = [t["name"] for t in responses[0]["result"]["tools"]]
    assert "list_files" in names  # the real server's own tool, untouched
    assert "aran_status" in names
    assert "aran_explain" in names


def test_aran_explain_checks_secret_and_supply_chain_categories_too(tmp_path: Path, fake_server_command: list[str]):
    """secret/supply_chain signatures only matter to the repo scan, but
    aran_explain should still be able to check text against them - it uses
    the same repo_signatures dict regardless of whether
    ARAN_SCAN_GITHUB_REPOS is enabled."""
    client_in = _requests_to_bytes([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aran_explain", "arguments": {"text": "AKIAABCDEFGHIJKLMNOP"}}},
    ])
    client_out = io.BytesIO()

    run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=client_in,
        client_out=client_out,
        secret_signatures=[r"AKIA[0-9A-Z]{16}"],
    )

    responses = _parse_responses(client_out)
    text = responses[0]["result"]["content"][0]["text"]
    assert "secret" in text
