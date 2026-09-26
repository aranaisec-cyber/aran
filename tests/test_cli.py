import io
import json
import sys

import pytest

from mcp_shield import cli


def test_parse_args_splits_on_separator():
    assert cli.parse_args(["--", "npx", "server", "--flag"]) == ["npx", "server", "--flag"]


def test_parse_args_raises_when_separator_missing():
    with pytest.raises(ValueError):
        cli.parse_args(["npx", "server"])


def test_parse_args_raises_when_command_empty():
    with pytest.raises(ValueError):
        cli.parse_args(["--"])


def test_main_returns_usage_error_when_separator_missing(capsys):
    code = cli.main(["npx", "server"], stdin=io.BytesIO(b""), stdout=io.BytesIO())
    assert code == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_main_end_to_end_blocks_destructive_command(tmp_path, monkeypatch, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}},
    }
    stdin = io.BytesIO((json.dumps(request) + "\n").encode("utf-8"))
    stdout = io.BytesIO()

    cli.main(["--", *fake_server_command], stdin=stdin, stdout=stdout)

    response = json.loads(stdout.getvalue().decode("utf-8").strip())
    assert response["error"]["code"] == -32000
