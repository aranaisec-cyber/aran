from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path
from typing import BinaryIO

from mcp_shield.audit import log_event
from mcp_shield.gates import check_input, check_output

RequestId = int | str | None


def _write_line(stream: BinaryIO, lock: threading.Lock, data: bytes) -> None:
    with lock:
        stream.write(data)
        stream.flush()


def _blocked_response(request_id: RequestId, message: str) -> bytes:
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32000, "message": message},
    }
    return (json.dumps(payload) + "\n").encode("utf-8")


def _pump_client_to_server(
    *,
    client_in: BinaryIO,
    server_in: BinaryIO,
    client_out: BinaryIO,
    client_out_lock: threading.Lock,
    output_signatures: list[str],
    audit_log_path: Path,
    pending_tool_calls: dict[RequestId, str],
    pending_lock: threading.Lock,
) -> None:
    while True:
        line = client_in.readline()
        if not line:
            break
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            server_in.write(line)
            server_in.flush()
            continue

        if message.get("method") == "tools/call":
            params = message.get("params") or {}
            tool_name = params.get("name", "")
            arguments = params.get("arguments") or {}
            matched = check_output(tool_name, arguments, output_signatures)
            if matched:
                log_event(
                    audit_log_path,
                    direction="outbound",
                    tool_name=tool_name,
                    outcome="blocked",
                    matched_signature=matched,
                )
                blocked = _blocked_response(
                    message.get("id"),
                    f"[Aran] blocked: outbound call matched signature {matched!r}",
                )
                _write_line(client_out, client_out_lock, blocked)
                continue
            log_event(
                audit_log_path,
                direction="outbound",
                tool_name=tool_name,
                outcome="allowed",
                matched_signature=None,
            )
            with pending_lock:
                pending_tool_calls[message.get("id")] = tool_name

        server_in.write(line)
        server_in.flush()

    server_in.close()


def _pump_server_to_client(
    *,
    server_out: BinaryIO,
    client_out: BinaryIO,
    client_out_lock: threading.Lock,
    input_signatures: list[str],
    audit_log_path: Path,
    pending_tool_calls: dict[RequestId, str],
    pending_lock: threading.Lock,
) -> None:
    while True:
        line = server_out.readline()
        if not line:
            break
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            _write_line(client_out, client_out_lock, line)
            continue

        request_id = message.get("id")
        with pending_lock:
            tool_name = pending_tool_calls.pop(request_id, None)

        if tool_name is not None and "result" in message:
            content = (message.get("result") or {}).get("content") or []
            blocked_any = False
            for block in content:
                text = block.get("text")
                if not isinstance(text, str):
                    continue
                matched = check_input(text, input_signatures)
                if matched:
                    blocked_any = True
                    block["text"] = (
                        "[Aran] content blocked: flagged as a probable "
                        "prompt injection"
                    )
            log_event(
                audit_log_path,
                direction="inbound",
                tool_name=tool_name,
                outcome="blocked" if blocked_any else "allowed",
                matched_signature=None,
            )
            line = (json.dumps(message) + "\n").encode("utf-8")

        _write_line(client_out, client_out_lock, line)

    server_out.close()


def run_proxy(
    command: list[str],
    *,
    input_signatures: list[str],
    output_signatures: list[str],
    audit_log_path: Path,
    client_in: BinaryIO,
    client_out: BinaryIO,
) -> int:
    """Spawns `command` as the real MCP server and relays JSON-RPC between
    client_in/client_out (the IDE side) and the child's stdio, applying the
    output gate to outbound tools/call requests and the input gate to
    inbound tool-call results. Returns the child process's exit code."""
    child = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
    )
    assert child.stdin is not None and child.stdout is not None

    client_out_lock = threading.Lock()
    pending_lock = threading.Lock()
    pending_tool_calls: dict[RequestId, str] = {}

    to_server = threading.Thread(
        target=_pump_client_to_server,
        kwargs=dict(
            client_in=client_in,
            server_in=child.stdin,
            client_out=client_out,
            client_out_lock=client_out_lock,
            output_signatures=output_signatures,
            audit_log_path=audit_log_path,
            pending_tool_calls=pending_tool_calls,
            pending_lock=pending_lock,
        ),
        daemon=True,
    )
    to_client = threading.Thread(
        target=_pump_server_to_client,
        kwargs=dict(
            server_out=child.stdout,
            client_out=client_out,
            client_out_lock=client_out_lock,
            input_signatures=input_signatures,
            audit_log_path=audit_log_path,
            pending_tool_calls=pending_tool_calls,
            pending_lock=pending_lock,
        ),
        daemon=True,
    )
    to_server.start()
    to_client.start()

    child.wait()
    to_client.join(timeout=2)
    return child.returncode
