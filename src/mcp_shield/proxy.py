from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, BinaryIO, Callable

from mcp_shield.audit import log_event
from mcp_shield.gates import check_input, check_output

RequestId = int | str | None

# Exit code returned when the relay itself degraded (a message could not be
# inspected, or a pump thread died) while the child process itself exited 0.
# Without this, a hostile server could disable the gate and the IDE would see
# a clean exit 0 with no indication anything went wrong.
EXIT_PROXY_DEGRADED = 3

REDACTION_NOTICE = "[Aran] content blocked: flagged as a probable prompt injection"

# Depth cap when walking a decoded server result. Real MCP results are
# shallow; deeper is either a bug or a payload aimed at the recursion limit.
_MAX_WALK_DEPTH = 200


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


def _warn(text: str) -> None:
    print(text, file=sys.stderr)


def _usable_request_id(value: Any) -> RequestId:
    """JSON-RPC ids are strings or numbers. Anything else (a list, a dict)
    is both invalid and unhashable, so it must never reach a dict lookup."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, str)):
        return value
    return None


def _is_response(message: dict) -> bool:
    """True only for a JSON-RPC *response*. MCP is bidirectional: the server
    issues its own requests and notifications (ping, sampling/createMessage,
    roots/list, elicitation/create) numbered from its own id counter, so
    server ids collide with the client's. Treating those as responses would
    consume the pending tool-call entry and silently disable the input gate
    for the real response that arrives later (C1)."""
    return "method" not in message and ("result" in message or "error" in message)


def _redact_strings(
    value: Any,
    signatures: list[str],
    matches: list[str],
    depth: int = 0,
) -> Any:
    """Recursively replaces every string leaf that matches an input-gate
    signature with the redaction notice, collecting what matched.

    Walking the whole decoded result (rather than only result.content[*].text)
    covers the channels that otherwise reach the agent unchecked: bare-string
    content blocks, result.structuredContent, and embedded-resource blocks'
    resource.text. Applied to message["error"] too, so injected text in
    error.message is inspected as well.

    Intentionally out of scope for v1: tools/list tool descriptions and
    server-originated requests/notifications, which the design specifies are
    passed through unmodified."""
    if depth > _MAX_WALK_DEPTH:
        raise ValueError("server result nested too deeply to inspect")
    if isinstance(value, str):
        matched = check_input(value, signatures)
        if matched:
            matches.append(matched)
            return REDACTION_NOTICE
        return value
    if isinstance(value, dict):
        return {k: _redact_strings(v, signatures, matches, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_strings(item, signatures, matches, depth + 1) for item in value]
    return value


def _gate_outbound_message(
    line: bytes,
    *,
    output_signatures: list[str],
    audit_log_path: Path,
    pending_tool_calls: dict[RequestId, str],
    pending_lock: threading.Lock,
    client_out: BinaryIO,
    client_out_lock: threading.Lock,
) -> bytes | None:
    """Applies the output gate to one client->server line. Returns the bytes to
    forward to the server, or None if the call was blocked (in which case the
    error response has already been written back to the client)."""
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        return line

    # A valid-JSON line that isn't an object has no method/params to gate.
    if not isinstance(message, dict) or message.get("method") != "tools/call":
        return line

    params = message.get("params")
    if not isinstance(params, dict):
        params = {}
    tool_name = params.get("name")
    if not isinstance(tool_name, str):
        tool_name = ""
    arguments = params.get("arguments")
    request_id = _usable_request_id(message.get("id"))

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
            request_id,
            f"[Aran] blocked: outbound call matched signature {matched!r}",
        )
        _write_line(client_out, client_out_lock, blocked)
        return None

    log_event(
        audit_log_path,
        direction="outbound",
        tool_name=tool_name,
        outcome="allowed",
        matched_signature=None,
    )
    # This write must happen before the line is forwarded, otherwise the
    # response can come back before the id is registered.
    with pending_lock:
        pending_tool_calls[request_id] = tool_name
    return line


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
    degraded: threading.Event,
) -> None:
    try:
        while True:
            line = client_in.readline()
            if not line:
                break
            try:
                forward = _gate_outbound_message(
                    line,
                    output_signatures=output_signatures,
                    audit_log_path=audit_log_path,
                    pending_tool_calls=pending_tool_calls,
                    pending_lock=pending_lock,
                    client_out=client_out,
                    client_out_lock=client_out_lock,
                )
            except Exception as e:  # noqa: BLE001 - see fail-closed note below
                # FAIL-CLOSED POLICY: a message we could not inspect is never
                # forwarded to the real server. The client still gets an error
                # response for its id (so it does not hang), the failure is
                # audited, and the proxy exits non-zero.
                degraded.set()
                _warn(f"[Aran] error: outbound message could not be inspected: {e!r}")
                log_event(
                    audit_log_path,
                    direction="outbound",
                    tool_name=None,
                    outcome="error",
                    matched_signature=None,
                )
                request_id = _safe_peek_id(line)
                if request_id is not None:
                    _write_line(
                        client_out,
                        client_out_lock,
                        _blocked_response(
                            request_id,
                            "[Aran] blocked: outbound message could not be inspected",
                        ),
                    )
                continue
            if forward is None:
                continue
            server_in.write(forward)
            server_in.flush()
    finally:
        # Always give the child EOF, even if the loop above blew up - otherwise
        # child.wait() in run_proxy can block forever.
        try:
            server_in.close()
        except OSError:
            pass


def _safe_peek_id(line: bytes) -> RequestId:
    try:
        message = json.loads(line)
    except Exception:  # noqa: BLE001 - best-effort id recovery only
        return None
    if not isinstance(message, dict):
        return None
    return _usable_request_id(message.get("id"))


def _gate_inbound_message(
    line: bytes,
    *,
    input_signatures: list[str],
    audit_log_path: Path,
    pending_tool_calls: dict[RequestId, str],
    pending_lock: threading.Lock,
) -> bytes:
    """Applies the input gate to one server->client line, returning the bytes
    to hand to the client (redacted if a signature matched)."""
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        return line

    if not isinstance(message, dict) or not _is_response(message):
        return line

    request_id = _usable_request_id(message.get("id"))
    with pending_lock:
        tool_name = pending_tool_calls.pop(request_id, None)
    if tool_name is None:
        return line

    matches: list[str] = []
    for key in ("result", "error"):
        if key in message:
            message[key] = _redact_strings(message[key], input_signatures, matches)

    log_event(
        audit_log_path,
        direction="inbound",
        tool_name=tool_name,
        outcome="blocked" if matches else "allowed",
        # Only the first match is recorded: the audit field is a single string
        # and one matched rule is what an operator needs to tune a false
        # positive. The payload itself is deliberately never logged or echoed.
        matched_signature=matches[0] if matches else None,
    )
    return (json.dumps(message) + "\n").encode("utf-8")


def _pump_server_to_client(
    *,
    server_out: BinaryIO,
    client_out: BinaryIO,
    client_out_lock: threading.Lock,
    input_signatures: list[str],
    audit_log_path: Path,
    pending_tool_calls: dict[RequestId, str],
    pending_lock: threading.Lock,
    degraded: threading.Event,
) -> None:
    try:
        while True:
            line = server_out.readline()
            if not line:
                break
            try:
                out_line = _gate_inbound_message(
                    line,
                    input_signatures=input_signatures,
                    audit_log_path=audit_log_path,
                    pending_tool_calls=pending_tool_calls,
                    pending_lock=pending_lock,
                )
            except Exception as e:  # noqa: BLE001 - see fail-closed note below
                # FAIL-CLOSED POLICY: inbound content that could not be
                # inspected is dropped rather than relayed - it would land
                # directly in the agent's context un-gated, which is the exact
                # thing this proxy exists to prevent. The drop is audited and
                # the proxy exits non-zero so the failure is visible.
                degraded.set()
                _warn(f"[Aran] error: inbound message could not be inspected, dropped: {e!r}")
                log_event(
                    audit_log_path,
                    direction="inbound",
                    tool_name=None,
                    outcome="error",
                    matched_signature=None,
                )
                continue
            _write_line(client_out, client_out_lock, out_line)
    finally:
        try:
            server_out.close()
        except OSError:
            pass


def _run_pump(target: Callable[..., None], kwargs: dict, degraded: threading.Event) -> None:
    """Runs a pump and records the fact if it dies, so run_proxy can report a
    non-zero exit code instead of looking like a clean run."""
    try:
        target(**kwargs)
    except BaseException as e:  # noqa: BLE001 - a dead pump must never be silent
        degraded.set()
        _warn(f"[Aran] error: relay thread {target.__name__} stopped: {e!r}")


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
    inbound tool-call results. Returns the child process's exit code, or
    EXIT_PROXY_DEGRADED if the relay itself failed while the child exited 0."""
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
    degraded = threading.Event()

    to_server = threading.Thread(
        target=_run_pump,
        args=(
            _pump_client_to_server,
            dict(
                client_in=client_in,
                server_in=child.stdin,
                client_out=client_out,
                client_out_lock=client_out_lock,
                output_signatures=output_signatures,
                audit_log_path=audit_log_path,
                pending_tool_calls=pending_tool_calls,
                pending_lock=pending_lock,
                degraded=degraded,
            ),
            degraded,
        ),
        daemon=True,
    )
    to_client = threading.Thread(
        target=_run_pump,
        args=(
            _pump_server_to_client,
            dict(
                server_out=child.stdout,
                client_out=client_out,
                client_out_lock=client_out_lock,
                input_signatures=input_signatures,
                audit_log_path=audit_log_path,
                pending_tool_calls=pending_tool_calls,
                pending_lock=pending_lock,
                degraded=degraded,
            ),
            degraded,
        ),
        daemon=True,
    )
    to_server.start()
    to_client.start()

    child.wait()
    to_client.join(timeout=2)
    if child.returncode == 0 and degraded.is_set():
        return EXIT_PROXY_DEGRADED
    return child.returncode
