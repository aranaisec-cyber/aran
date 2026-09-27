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

# How many levels of JSON-RPC batch array either gate will unwrap. One level is
# the only legal shape; a batch inside a batch is already non-conformant, so a
# couple of levels of tolerance is generosity and anything past this cap is a
# payload aimed at the recursion limit - it takes the fail-closed path.
_MAX_BATCH_NESTING = 8

# How many levels of JSON-RPC batch array the *id-recovery* walk
# (_iter_message_objects) will unwrap when looking for an id to answer for a
# message the gate refused to relay. This is deliberately several times
# _MAX_BATCH_NESTING rather than equal to it: a message nested one or two
# layers past the drop cap is still a realistic (if hostile) payload, and the
# client sending it still deserves a synthesized error reply instead of a
# silent hang. Every message the gate drops for excessive nesting must remain
# within this budget, with real headroom to spare - not just the same
# boundary the drop cap uses. It is still a finite cap, not unbounded
# recursion: past this depth the payload is aimed at the recursion/stack
# limit itself, and the proxy accepts that such a message loses its reply
# rather than let id-recovery become its own resource-exhaustion vector.
_ID_RECOVERY_MAX_NESTING = _MAX_BATCH_NESTING * 3


def _write_line(stream: BinaryIO, lock: threading.Lock, data: bytes) -> None:
    with lock:
        stream.write(data)
        stream.flush()


def _blocked_payload(request_id: RequestId, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32000, "message": message},
    }


def _blocked_response(request_id: RequestId, message: str) -> bytes:
    return _encode_json_line(_blocked_payload(request_id, message))


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


# --- The rewrite rule: a fail-closed denylist of protocol machinery ----------
#
# Every string leaf of an inbound result/error is *scanned* unconditionally -
# that is what closes the N1/R1 bypass class and does not change here. What
# changed (round 4, C-A/C-B) is the *rewrite* decision. Enumerating the
# content-bearing positions instead - an allowlist of exact field paths - was
# fail-open by construction: anything nobody thought to list was relayed
# verbatim, which lost `result.instructions` and tool `inputSchema` parameter
# descriptions (both agent-visible by spec), and let a hostile server evade
# redaction outright just by sending content in an unexpected-but-still-parsed
# shape (`content` as a bare string, `contents` as a list of strings,
# `messages[*].content` as a list, `tools` as an object, ...).
#
# The rule is now inverted: redact by default, exempt only protocol machinery,
# and decide the exemption from the leaf's own field NAME rather than its exact
# path. A misnested field still carries its name, so the same decision is
# reached whatever shape it arrives in - and a field nobody enumerated defaults
# to protected rather than exposed.

# Machinery keys: the value under one of these names is consumed structurally by
# the client or the protocol. Replacing it breaks the session (negotiation,
# pagination) or the client's ability to address the thing it names (a tool to
# call, a resource to fetch, a content block to render) - without protecting the
# agent, because none of it is prose the model reads as server output.
# Deliberately NOT here: `description`, `title`, `instructions`, `text`, `data`
# and everything else - those are the injection channels redaction exists for.
_MACHINERY_KEYS = frozenset({
    "protocolVersion",       # initialize negotiation
    "nextCursor", "cursor",  # pagination tokens
    "name",                  # identifier - but see _NAMED_ENTRY_PARENTS
    "uri", "uriTemplate",    # resource addresses
    "mimeType",              # content-block media type
    "blob",                  # base64 payload of a binary content block
    "type",                  # content-block discriminator: text/image/resource
    "role",                  # "user"/"assistant"
})

# `name` is the one denylisted key MCP genuinely uses both ways, so its
# exemption is conditional. It is an identifier where the thing being named is
# something the client addresses by name - a tool it calls, a prompt/resource/
# template it requests, a prompt argument, an implementation it negotiates with
# (`serverInfo`, covered as a subtree below) - and redacting one of those breaks
# the client's ability to use it at all. Inside a content block it is display
# text the agent reads (a resource_link's `name`, for instance), so the
# exemption does not apply there and such a name is redacted like any other
# content. This is a *narrowing* of an exemption, decided by an ancestor's field
# name rather than an exact path, so it holds under reshaped payloads too.
_NAMED_ENTRY_PARENTS = frozenset({
    "tools", "prompts", "resources", "resourceTemplates", "arguments",
})

# Machinery subtree exempt by bare name at ANY depth: `_meta` is the
# protocol's reserved extension slot, and per the round-4 review any MCP
# object may legitimately carry one, so there is no single position to anchor
# it to.
_MACHINERY_SUBTREES = frozenset({"_meta"})

# Machinery subtrees exempt only at their legitimate position: everything at
# or under `result.capabilities` or `result.serverInfo` is negotiation (and
# carries nested fields - `version`, per-capability flags - not worth
# enumerating one by one), but both keys are only legitimate as immediate
# children of a top-level `initialize` result. Exempting them by bare name
# anywhere (as `_meta` still is, above) let a hostile server fabricate an
# exempt region wherever it liked, by nesting a `capabilities` or
# `serverInfo` key inside ordinary content (e.g.
# `result.content[0].capabilities.hint`). Anchoring the first two path
# segments narrows the exemption to where it is real, the same direction
# `error.code`'s exact-path anchor already narrows that one.
_MACHINERY_SUBTREE_ANCHORS = frozenset({
    ("result", "capabilities"),
    ("result", "serverInfo"),
})

# `error.code` is machinery (clients switch on it), but `code` anywhere else is
# just a field name a server can put prose in, so this one exemption stays
# anchored to its exact position. Anchoring *narrows* an exemption, which is the
# fail-closed direction; a path is never used to grant one.
_MACHINERY_PATHS = frozenset({("error", "code")})

# Subtrees that are free-form server/tool output by definition, where no
# protocol machinery lives: inside them the exemptions above do not apply. A
# tool that returns {"name": "..."} in its structured output is returning
# content the agent reads, not an identifier the client resolves.
_CONTENT_SUBTREES = frozenset({"structuredContent"})


def _rewrite_allowed(path: tuple[Any, ...]) -> bool:
    """Whether a matched string leaf at `path` is replaced with the redaction
    notice. `path` starts at the top-level member being walked - ("result", ...)
    or ("error", ...) - with _INDEX standing in for a list position.

    The answer is True (redact) unless the leaf is protocol machinery; see the
    denylist above for why it is an exemption list rather than an allowlist.

    The exemption is decided by field name at any depth, never by exact path. A
    list index is not a field name, so the governing name for a leaf inside a
    list is the member the list hangs off: `content` sent as a bare string, as a
    single dict, or as a list of bare strings all resolve to `content` - not on
    the denylist, therefore redacted - and `tools` sent as an object instead of
    an array still reaches `description` for its leaf.

    Several exemptions are narrowed by context (never widened): `error.code`,
    `capabilities`/`serverInfo` outside a top-level `result`, and `name`
    outside a named-entry parent. See the constants above."""
    if path in _MACHINERY_PATHS:
        return False
    keys = [p for p in path if isinstance(p, str)]
    if any(key in _CONTENT_SUBTREES for key in keys):
        return True
    if any(key in _MACHINERY_SUBTREES for key in keys):
        return False
    if path[:2] in _MACHINERY_SUBTREE_ANCHORS:
        return False
    if not keys:
        return True
    own_key = keys[-1]
    if own_key == "name":
        return not any(key in _NAMED_ENTRY_PARENTS for key in keys[:-1])
    return own_key not in _MACHINERY_KEYS


def _scan_and_redact(
    value: Any,
    signatures: SignatureList,
    matches: list[str],
    redactions: list[str],
    *,
    path: tuple[Any, ...],
    depth: int = 0,
) -> Any:
    """Walks every string leaf under `value`, checking each against the input
    gate and replacing every match with the redaction notice except where
    _rewrite_allowed exempts it as protocol machinery.

    Walking the whole decoded result (rather than only result.content[*].text)
    covers the channels that otherwise reach the agent unchecked: bare-string
    content blocks, result.structuredContent, embedded-resource blocks'
    resource.text, result.instructions, inputSchema parameter descriptions,
    tools/list descriptions, and error.message.

    `matches` collects everything that matched (for audit visibility);
    `redactions` collects only what was actually rewritten, which is what makes
    a message "blocked". See _rewrite_allowed for the machinery denylist.

    Dict KEYS are scanned too (matched signatures recorded into `matches`,
    same as an exempted value leaf), but a matching key is never rewritten:
    only VALUE leaves are ever replaced. `structuredContent` is arbitrary JSON
    per the MCP spec, so a server can put attacker-chosen text in a key with
    no unusual shape required - scanning it closes the one channel that
    otherwise left zero audit trail at all, matched_signature included. Key
    rewriting is a deliberately separate, harder problem (redacting one of two
    keys that collide to the same placeholder, or touching a machinery key
    like `type`/`role`) left for a future pass; this is audit-only."""
    if depth > _MAX_WALK_DEPTH:
        raise ValueError("server result nested too deeply to inspect")
    if isinstance(value, str):
        matched = check_input(value, signatures)
        if matched is None:
            return value
        matches.append(matched)
        if _rewrite_allowed(path):
            redactions.append(matched)
            return REDACTION_NOTICE
        return value
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            if isinstance(k, str):
                key_matched = check_input(k, signatures)
                if key_matched is not None:
                    matches.append(key_matched)
            result[k] = _scan_and_redact(
                v, signatures, matches, redactions,
                path=path + (k,), depth=depth + 1,
            )
        return result
    if isinstance(value, list):
        return [
            _scan_and_redact(
                item, signatures, matches, redactions,
                path=path + (_INDEX,), depth=depth + 1,
            )
            for item in value
        ]
    return value


class _Dropped:
    """Marks an outbound element the gate refuses to forward."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<dropped>"


_DROP = _Dropped()


def _gate_outbound_object(
    message: dict,
    *,
    output_signatures: SignatureList,
    audit_log_path: Path,
    pending_tool_calls: dict[RequestId, str],
    pending_lock: threading.Lock,
    blocked: list[tuple[RequestId, str]],
) -> Any:
    """Gates one client->server JSON-RPC object. Returns the object to forward,
    or _DROP when the call is blocked - in which case (id, message) is appended
    to `blocked` so the caller can answer the client in the framing the client
    used."""
    if message.get("method") != "tools/call":
        return message

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
        blocked.append(
            (request_id, f"[Aran] blocked: outbound call matched signature {matched!r}")
        )
        return _DROP

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
    return message


def _gate_outbound_value(value: Any, *, depth: int = 0, **gate: Any) -> Any:
    """Gates one outbound value, unwrapping JSON-RPC batch framing.

    A `tools/call` wrapped in a batch array used to reach the real server
    completely ungated, because the parsed top-level value was a list rather
    than a dict - the same shape-dependent blindness N1 fixed on the inbound
    side, still open here (I-A). Every element of an array is gated
    individually; blocked elements are removed and the rest are forwarded with
    the batch framing intact, mirroring how the inbound batch case gates
    element-by-element instead of judging the batch as a whole."""
    if isinstance(value, list):
        if depth >= _MAX_BATCH_NESTING:
            raise ValueError("outbound batch nested too deeply to inspect")
        if not value:
            return value
        kept = [
            gated
            for gated in (
                _gate_outbound_value(element, depth=depth + 1, **gate) for element in value
            )
            if gated is not _DROP
        ]
        return kept if kept else _DROP
    if isinstance(value, dict):
        return _gate_outbound_object(value, **gate)
    # A valid-JSON line that is neither object nor array has no method/params
    # to gate.
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
    forward to the server, or None if everything in the line was blocked (in
    which case the error response has already been written back to the client)."""
    try:
        message = _decode_json_line(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return line

    blocked: list[tuple[RequestId, str]] = []
    gated = _gate_outbound_value(
        message,
        output_signatures=output_signatures,
        audit_log_path=audit_log_path,
        pending_tool_calls=pending_tool_calls,
        pending_lock=pending_lock,
        blocked=blocked,
    )

    if blocked:
        # Every blocked call the client can be answered for gets an error for
        # its own id, in the framing it was sent in: one object for a plain
        # request, an array for a batch. A blocked element with no usable id is
        # a notification - there is nothing to answer.
        payloads = [_blocked_payload(rid, text) for rid, text in blocked if rid is not None]
        if payloads:
            _write_line(
                client_out,
                client_out_lock,
                _encode_json_line(payloads if isinstance(message, list) else payloads[0]),
            )

    if gated is _DROP:
        return None
    if gated == message:
        # Nothing was removed: forward the original bytes, so a line the gate
        # did not change reaches the server exactly as the client wrote it.
        return line
    return _encode_json_line(gated)


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


def _iter_message_objects(value: Any, depth: int = 0):
    """Yields every JSON-RPC-object-shaped value in `value`, unwrapping batch
    arrays (including nested ones). Best-effort: used only for id recovery, so
    it stops at its own nesting cap rather than raising.

    This walk uses `_ID_RECOVERY_MAX_NESTING`, not `_MAX_BATCH_NESTING`: the
    two gates (`_gate_inbound_batch` / `_gate_outbound_value`) drop a message
    as soon as it is nested one layer past `_MAX_BATCH_NESTING`, and a budget
    here that merely matched that cap could recover an id only for a message
    nested *exactly* at that boundary - anything one layer deeper reproduced
    the original silent-hang bug this helper exists to prevent (K2). Using a
    materially larger budget (several times the drop cap) means realistic
    attacker payloads nested a few layers past the boundary still get an id
    recovered and answered, not just the single boundary case. It remains a
    finite cap rather than unbounded recursion, so a payload aimed at the
    recursion/stack limit itself still just loses its reply instead of
    crashing or hanging the pump."""
    if isinstance(value, dict):
        yield value
    elif isinstance(value, list) and depth <= _ID_RECOVERY_MAX_NESTING:
        for element in value:
            yield from _iter_message_objects(element, depth + 1)


def _safe_peek_id(line: bytes) -> RequestId:
    """Best-effort recovery of the id to answer for a line that had to be
    dropped, so a client waiting on that request gets a reply (R2) instead of
    hanging. One synthesized error is all a single line can carry back.

    A *response*-shaped element's id wins over any other element's id: in a
    batch, a server-originated request sitting next to the response carries an
    id from the server's own numbering, and answering that one would leave the
    client waiting forever for the id it actually sent."""
    try:
        message = _decode_json_line(line)
    except Exception:  # noqa: BLE001 - best-effort id recovery only
        return None
    objects = list(_iter_message_objects(message))
    for responses_only in (True, False):
        for element in objects:
            if responses_only and not _is_response(element):
                continue
            if "id" not in element:
                continue
            request_id = _usable_request_id(element.get("id"))
            if request_id is not None:
                return request_id
    return None


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
            # A result/error that is not an object at all (a bare string, a
            # list) is non-conformant: it holds no protocol machinery to
            # preserve, only content. No special case is needed for it any more
            # - the denylist keys off field names, and a value reached without
            # passing through a machinery field name is content by default (C2).
            message[key] = _scan_and_redact(
                message[key],
                input_signatures,
                matches,
                redactions,
                path=(key,),
            )

    log_event(
        audit_log_path,
        direction="inbound",
        tool_name=tool_name,
        # "blocked" means content was actually rewritten. A match in an exempt
        # machinery field (protocolVersion, tool name, resource uri, ... - see
        # _rewrite_allowed) is still named in the record for
        # false-positive tuning, but the message was relayed as it arrived.
        outcome="blocked" if redactions else "allowed",
        # Only the first match is recorded: the audit field is a single string
        # and one matched rule is what an operator needs to tune a false
        # positive. The payload itself is deliberately never logged or echoed.
        matched_signature=(redactions or matches or [None])[0],
    )


def _gate_inbound_batch(elements: list, *, depth: int, gate: dict) -> bool:
    """Gates every response-shaped element of a batch array in place, and
    returns whether anything was gated (i.e. whether the line has to be
    re-encoded).

    Nested batch arrays are recursed into rather than skipped: an element that
    is a list, not a dict, used to fall through with no gating and no audit
    record at all - the same "not the expected shape, therefore not inspected"
    hole N1 closed one level up. The nesting cap raises instead of recursing
    forever, which puts an absurdly nested line on the caller's fail-closed
    path (dropped, audited, answered) rather than relaying it."""
    gated = False
    for element in elements:
        if isinstance(element, list):
            if depth >= _MAX_BATCH_NESTING:
                raise ValueError("inbound batch nested too deeply to inspect")
            if _gate_inbound_batch(element, depth=depth + 1, gate=gate):
                gated = True
        elif isinstance(element, dict) and _is_response(element):
            _gate_response_object(element, **gate)
            gated = True
    return gated


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
        if not _gate_inbound_batch(message, depth=1, gate=gate):
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
