from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, BinaryIO, Callable

from mcp_shield.audit import log_event
from mcp_shield.gates import SignatureList, check_input, check_output, compile_signatures

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

# Cap on the pending tool-call map. Entries are no longer consumed when a
# response arrives (see _gate_inbound_message), so they are evicted oldest-first
# at registration time instead. The map only supplies the tool_name label for
# inbound audit records, so losing the oldest entries in a session with more
# than this many in-flight calls costs an audit label, never a gate check.
_MAX_PENDING_TOOL_CALLS = 4096


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


def _decode_json_line(line: bytes) -> Any:
    """Parses one wire line as JSON, preserving json's own encoding detection.

    json.loads() on bytes sniffs the encoding from a BOM (utf-8-sig, utf-16,
    utf-32), so it must get the raw bytes first: forcing
    line.decode("utf-8", errors="replace") threw that detection away and turned
    a BOM-prefixed or UTF-16 line into an unparseable one, which the inbound
    pump then relayed raw and un-gated (N2).

    Only when the bytes are not decodable at all does the lossy fallback apply.
    json.loads() raises UnicodeDecodeError there, a ValueError *sibling* of
    json.JSONDecodeError rather than a subclass, so it escapes an
    `except json.JSONDecodeError` and would otherwise carry a perfectly
    inspectable message off to the fail-closed path (R3). Decoding with
    errors="replace" keeps the message inspectable: the gate sees the text and
    only the undecodable bytes themselves are lost."""
    try:
        return json.loads(line)
    except UnicodeDecodeError:
        return json.loads(line.decode("utf-8", errors="replace"))


def _encode_json_line(message: Any) -> bytes:
    return (json.dumps(message) + "\n").encode("utf-8")


def _is_response(message: dict) -> bool:
    """True for anything response-shaped: a `result` or an `error` member is
    present, whatever else the message carries.

    The decision deliberately does NOT look at `method`. MCP is bidirectional -
    the server issues its own requests and notifications (ping,
    sampling/createMessage, roots/list, elicitation/create) and those are passed
    through unmodified by design - but a genuine request or notification never
    carries `result`/`error`, so keying off those two members is enough to let
    real server-originated traffic through. Keying off the *absence of a method
    key* was not: `{"id":1,"method":null,"result":{...injection...}}` (likewise
    `"method":0` and `"method":""`) skipped the gate entirely while a client that
    resolves messages structurally - id + result means response - still delivered
    the payload (N1). The proxy's guarantee must not depend on the IDE's parser
    being stricter than the proxy's own."""
    return "result" in message or "error" in message


class _ListIndex:
    """Marks 'an element of a list' in a redaction path."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "[*]"


_INDEX = _ListIndex()


# Rewritable positions inside a `result`, as {list-bearing member: allowed tails
# within one of its elements}. A tail of () means the element itself is a string.
# Everything here is content or a description the agent reads as server output;
# nothing here is protocol machinery. The two content-block shapes are MCP's
# `content` (tools/call, prompts) and `contents` (resources/read).
_REWRITABLE_ELEMENT_TAILS: dict[str, set[tuple[str, ...]]] = {
    "content": {(), ("text",), ("resource", "text")},
    "contents": {("text",)},
    "messages": {("content", "text"), ("content", "resource", "text")},
    "tools": {("description",)},
    "prompts": {("description",)},
    "resources": {("description",)},
    "resourceTemplates": {("description",)},
}

# Rewritable members directly under `result`: the prompt description a
# prompts/get returns, and structuredContent (matched recursively, below).
_REWRITABLE_RESULT_KEYS = {"description"}


def _rewrite_allowed(path: tuple[Any, ...]) -> bool:
    """Whether the string leaf reached by `path` is one of the agent-visible
    content positions Aran rewrites (N4). `path` starts at the top-level member
    being walked - ("result", ...) or ("error", ...) - with _INDEX standing in
    for a list position.

    Every string leaf is *scanned* (that is what closes the bypass class behind
    N1/R1), but rewriting the ones that are protocol machinery rather than
    content broke session/capability negotiation whenever a signature happened
    to match `protocolVersion`, `serverInfo.name`, `nextCursor` or a tool's
    `name`, and destroyed unrelated tools' metadata. Those are now
    scanned-but-relayed-verbatim. Descriptions stay rewritable on purpose: a
    poisoned tool description is the real injection vector the wider scanning was
    added for."""
    root, rest = path[0], path[1:]
    if root == "error":
        return rest == ("message",)
    # root == "result"
    if not rest:
        # `result` is itself a string: a non-conformant result (MCP requires an
        # object) carrying content directly. Nothing to preserve for the
        # protocol's sake, so it is treated as content. See _gate_response_object
        # for the list/scalar case.
        return True
    head = rest[0]
    if head == "structuredContent":
        return True  # recursively: all of it is tool output the agent reads
    if len(rest) == 1:
        return head in _REWRITABLE_RESULT_KEYS
    if len(rest) >= 2 and rest[1] is _INDEX:
        return rest[2:] in _REWRITABLE_ELEMENT_TAILS.get(head, ())
    return False


def _scan_and_redact(
    value: Any,
    signatures: SignatureList,
    matches: list[str],
    redactions: list[str],
    *,
    path: tuple[Any, ...],
    depth: int = 0,
    force_rewrite: bool = False,
) -> Any:
    """Walks every string leaf under `value`, checking each against the input
    gate and replacing the ones in a rewritable position with the redaction
    notice.

    Walking the whole decoded result (rather than only result.content[*].text)
    covers the channels that otherwise reach the agent unchecked: bare-string
    content blocks, result.structuredContent, embedded-resource blocks'
    resource.text, tools/list descriptions, and error.message.

    `matches` collects everything that matched (for audit visibility);
    `redactions` collects only what was actually rewritten, which is what makes
    a message "blocked". See _rewrite_allowed for the rewrite allowlist."""
    if depth > _MAX_WALK_DEPTH:
        raise ValueError("server result nested too deeply to inspect")
    if isinstance(value, str):
        matched = check_input(value, signatures)
        if matched is None:
            return value
        matches.append(matched)
        if force_rewrite or _rewrite_allowed(path):
            redactions.append(matched)
            return REDACTION_NOTICE
        return value
    if isinstance(value, dict):
        return {
            k: _scan_and_redact(
                v, signatures, matches, redactions,
                path=path + (k,), depth=depth + 1, force_rewrite=force_rewrite,
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [
            _scan_and_redact(
                item, signatures, matches, redactions,
                path=path + (_INDEX,), depth=depth + 1, force_rewrite=force_rewrite,
            )
            for item in value
        ]
    return value


def _gate_outbound_message(
    line: bytes,
    *,
    output_signatures: SignatureList,
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
        message = _decode_json_line(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
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
        # Bounded oldest-first, because the inbound side no longer removes
        # entries: whether an id is tracked must never decide whether a
        # response is gated (R1), so eviction is decoupled from gating.
        while len(pending_tool_calls) > _MAX_PENDING_TOOL_CALLS:
            del pending_tool_calls[next(iter(pending_tool_calls))]
    return line


def _pump_client_to_server(
    *,
    client_in: BinaryIO,
    server_in: BinaryIO,
    client_out: BinaryIO,
    client_out_lock: threading.Lock,
    output_signatures: SignatureList,
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
        message = _decode_json_line(line)
    except Exception:  # noqa: BLE001 - best-effort id recovery only
        return None
    if isinstance(message, list):
        # A batch that had to be dropped: answer for the first id in it, so a
        # client waiting on that request still gets a reply (R2) instead of
        # hanging. One synthesized error is all a single line can carry back.
        for element in message:
            if isinstance(element, dict) and "id" in element:
                return _usable_request_id(element.get("id"))
        return None
    if not isinstance(message, dict):
        return None
    return _usable_request_id(message.get("id"))


def _gate_response_object(
    message: dict,
    *,
    input_signatures: SignatureList,
    audit_log_path: Path,
    pending_tool_calls: dict[RequestId, str],
    pending_lock: threading.Lock,
) -> None:
    """Gates one response-shaped JSON-RPC object in place, and audits it."""
    request_id = _usable_request_id(message.get("id"))
    with pending_lock:
        tool_name = pending_tool_calls.get(request_id)

    matches: list[str] = []
    redactions: list[str] = []
    for key in ("result", "error"):
        if key in message:
            value = message[key]
            # A result/error that is not an object at all (a bare string, a
            # list) is non-conformant: it holds no protocol machinery to
            # preserve, only content, so everything in it is rewritable (C2).
            message[key] = _scan_and_redact(
                value,
                input_signatures,
                matches,
                redactions,
                path=(key,),
                force_rewrite=not isinstance(value, dict),
            )

    log_event(
        audit_log_path,
        direction="inbound",
        tool_name=tool_name,
        # "blocked" means content was actually rewritten. A match in a
        # scanned-but-not-rewritten field (protocolVersion, tool name, resource
        # uri, ... - see _rewrite_allowed) is still named in the record for
        # false-positive tuning, but the message was relayed as it arrived.
        outcome="blocked" if redactions else "allowed",
        # Only the first match is recorded: the audit field is a single string
        # and one matched rule is what an operator needs to tune a false
        # positive. The payload itself is deliberately never logged or echoed.
        matched_signature=(redactions or matches or [None])[0],
    )


def _gate_inbound_message(
    line: bytes,
    *,
    input_signatures: SignatureList,
    audit_log_path: Path,
    pending_tool_calls: dict[RequestId, str],
    pending_lock: threading.Lock,
) -> bytes:
    """Applies the input gate to one server->client line, returning the bytes
    to hand to the client (redacted if a signature matched).

    The gate runs on *every* response-shaped message, whether or not its id is
    one the proxy is tracking. Making a pending-id lookup the precondition for
    gating was the root cause behind C1/C2 (R1): because the lookup consumed
    the entry, any message a hostile server could get past the gate cheaply -
    an empty `{"id":1,"result":{}}`, or one deliberately crafted to be
    un-inspectable and dropped - retired the tracking entry, and the real
    injected response that followed for the same id was then "untracked" and
    relayed to the agent raw. There is deliberately no longer any message shape
    that skips the gate by virtue of not being tracked; pending_tool_calls is
    now only a lookup (.get, never .pop) supplying the audit record's
    tool_name label.

    A parse failure is NOT swallowed here: it propagates so the caller's
    fail-closed path drops the line instead of relaying content the gate never
    saw (N2). Top-level arrays (JSON-RPC batches) are unpacked and their
    response-shaped elements gated individually, because `isinstance(message,
    dict)` being false was itself a raw-relay bypass (N1)."""
    if not line.strip():
        # A blank line (keepalive, trailing newline) carries nothing to inspect.
        # It must not take the fail-closed path: that would degrade the whole
        # session over a harmless line.
        return line

    message = _decode_json_line(line)

    gate = dict(
        input_signatures=input_signatures,
        audit_log_path=audit_log_path,
        pending_tool_calls=pending_tool_calls,
        pending_lock=pending_lock,
    )

    if isinstance(message, dict):
        if not _is_response(message):
            return line
        _gate_response_object(message, **gate)
        return _encode_json_line(message)

    if isinstance(message, list):
        # JSON-RPC 2.0 batch framing (also in MCP's 2025-03-26 revision): gate
        # every response-shaped element, leave server-originated elements alone,
        # and hand the batch back with its framing intact.
        gated = False
        for element in message:
            if isinstance(element, dict) and _is_response(element):
                _gate_response_object(element, **gate)
                gated = True
        if not gated:
            return line
        return _encode_json_line(message)

    # Valid JSON that is neither an object nor an array (a bare scalar) cannot
    # be a JSON-RPC message at all and carries no response for a client to
    # unpack; it is relayed as-is.
    return line


def _pump_server_to_client(
    *,
    server_out: BinaryIO,
    client_out: BinaryIO,
    client_out_lock: threading.Lock,
    input_signatures: SignatureList,
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
                # Dropping the message must not also drop the *reply*: if this
                # was the only answer to a request the IDE is still waiting on,
                # silence hangs it forever (R2). Mirror the outbound half of
                # this policy and synthesize an error for the recovered id.
                request_id = _safe_peek_id(line)
                if request_id is not None:
                    _write_line(
                        client_out,
                        client_out_lock,
                        _blocked_response(
                            request_id,
                            "[Aran] blocked: inbound message could not be inspected",
                        ),
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
    input_signatures: SignatureList,
    output_signatures: SignatureList,
    audit_log_path: Path,
    client_in: BinaryIO,
    client_out: BinaryIO,
) -> int:
    """Spawns `command` as the real MCP server and relays JSON-RPC between
    client_in/client_out (the IDE side) and the child's stdio, applying the
    output gate to outbound tools/call requests and the input gate to every
    inbound JSON-RPC response. Returns the child process's exit code, or
    EXIT_PROXY_DEGRADED if the relay itself failed while the child exited 0.

    Signatures are compiled once here rather than per string leaf: the input
    gate now runs over every leaf of every response, so re-resolving ~200
    patterns through re.search() per leaf cost seconds on a large payload and
    made the single-threaded inbound relay look like a hang (N3)."""
    compiled_input = compile_signatures(input_signatures)
    compiled_output = compile_signatures(output_signatures)

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
                output_signatures=compiled_output,
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
                input_signatures=compiled_input,
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
