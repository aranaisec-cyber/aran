from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO, Callable

from aran.allowlist import is_trusted_repo
from aran.approvals import ApprovalContext, KIND_REPO_SCAN, KIND_SIGNATURE, call_key, describe_risk
from aran.audit import log_event
from aran.gates import (
    GitHubRepoRef,
    SignatureList,
    check_input,
    check_output,
    compile_signatures,
    find_github_repo_reference,
    locate_output_match,
)
from aran.loop_guard import DEFAULT_THRESHOLD, DEFAULT_WINDOW_SECONDS, LoopGuard
from aran.repo_scan import FetchTarballFn, default_fetch_tarball, scan_repo
from aran.status import (
    EXPLAIN_TOOL_DEFINITION,
    EXPLAIN_TOOL_NAME,
    PROXY_INSTRUCTIONS,
    STATUS_TOOL_DEFINITION,
    STATUS_TOOL_NAME,
    build_explain_report,
    build_status_report,
)

RequestId = int | str | None

# Exit code returned when the relay itself degraded (a message could not be
# inspected, or a pump thread died) while the child process itself exited 0.
# Without this, a hostile server could disable the gate and the IDE would see
# a clean exit 0 with no indication anything went wrong.
EXIT_PROXY_DEGRADED = 3

# -32000 (generic, existing) is reserved for "the proxy could not inspect this
# message" - a proxy-side failure. -32001 is specifically "a destructive
# signature matched", so an IDE (or a developer reading stderr) can tell "the
# gate worked as designed" apart from "something in Aran broke" at a glance,
# not just by parsing the message string.
CODE_SIGNATURE_BLOCKED = -32001

# A call blocked because the GitHub repo it references failed the optional
# repo scan (ARAN_SCAN_GITHUB_REPOS=1) - distinct from -32001 because the
# call's OWN arguments never matched anything; the problem is in the
# repo's content, not in the call itself.
CODE_REPO_SCAN_BLOCKED = -32002

# A call blocked by the optional loop guard (ARAN_LOOP_GUARD=1) - the same
# call, identical arguments, repeated past its threshold inside the
# tracking window. Distinct from -32001: no signature matched anything,
# the call itself may be entirely benign - it's the repetition that's the
# problem, not the content.
CODE_LOOP_GUARD_BLOCKED = -32003

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


def _blocked_payload(
    request_id: RequestId,
    message: str,
    *,
    code: int = -32000,
    data: dict | None = None,
) -> dict:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _blocked_response(
    request_id: RequestId,
    message: str,
    *,
    code: int = -32000,
    data: dict | None = None,
) -> bytes:
    return _encode_json_line(_blocked_payload(request_id, message, code=code, data=data))


def _status_payload(request_id: RequestId, text: str) -> dict:
    """A normal, successful tool-call result - the aran_status meta-tool
    (status.py) never fails the way a real tool call might, so unlike
    _blocked_payload this has no error/code/data branch."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}]},
    }


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
    audit_only: bool = False,
    leaf_count: list[int] | None = None,
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
        if leaf_count is not None:
            leaf_count[0] += 1
        matched = check_input(value, signatures)
        if matched is None:
            return value
        matches.append(matched)
        if _rewrite_allowed(path):
            redactions.append(matched)
            # audit_only: record that this WOULD have been redacted (drives
            # the "would_block" outcome below) but return the original value
            # unchanged - ARAN_MODE=audit never rewrites content.
            if audit_only:
                return value
            return REDACTION_NOTICE
        return value
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            if isinstance(k, str):
                if leaf_count is not None:
                    leaf_count[0] += 1
                key_matched = check_input(k, signatures)
                if key_matched is not None:
                    matches.append(key_matched)
            result[k] = _scan_and_redact(
                v, signatures, matches, redactions,
                path=path + (k,), depth=depth + 1,
                audit_only=audit_only, leaf_count=leaf_count,
            )
        return result
    if isinstance(value, list):
        return [
            _scan_and_redact(
                item, signatures, matches, redactions,
                path=path + (_INDEX,), depth=depth + 1,
                audit_only=audit_only, leaf_count=leaf_count,
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


def _consume_approval(approvals: ApprovalContext | None, tool_name: str, arguments: Any) -> bool:
    """Whether a human has approved this exact call (tool name + arguments).
    A store that can't be read means "not approved" - the block stands."""
    if approvals is None:
        return False
    try:
        return approvals.store.consume_approval(call_key(tool_name, arguments))
    except OSError:
        return False


def _offer_approval(
    approvals: ApprovalContext | None,
    *,
    tool_name: str,
    arguments: Any,
    kind: str,
    matched_signature: str | None,
    target_node: str | None,
    risk_detail: dict | None,
    message: str,
    data: dict,
) -> tuple[str, dict, str | None]:
    """Turns a plain block into "blocked, awaiting a human": parks the call as
    a pending approval, tells a human (desktop dialog) the first time, and
    adds the code to the error the agent sees. Returns (message, data, code).

    Nothing attacker-controlled is echoed into the message - only Aran's own
    signature text and a code - since the agent reads it. Any failure to
    reach the store leaves the original block untouched (fail closed)."""
    if approvals is None:
        return message, data, None
    key = call_key(tool_name, arguments)
    try:
        if approvals.store.status(key) == "declined":
            return (
                message + ". The user previously declined this exact call, so Aran will not ask again.",
                {**data, "approval": {"status": "declined"}},
                None,
            )
        pending, created = approvals.store.get_or_create_pending(
            key,
            tool_name=tool_name,
            arguments=arguments,
            kind=kind,
            matched_signature=matched_signature,
            target_node=target_node,
            risk=describe_risk(kind, matched_signature, risk_detail),
        )
    except OSError as e:
        _warn(f"[Aran] warning: could not record an approval request ({e}); the call stays blocked")
        return message, data, None
    if created and approvals.notify is not None:
        approvals.notify(pending)
    remaining = max(0, int(pending.expires_at - approvals.store.clock()))
    prompt_note = ", or through the desktop prompt" if approvals.notify is not None else ""
    return (
        f"{message} - awaiting human approval (code {pending.code}). Tell the user: they can review "
        f"and approve this exact call with `aran approve {pending.code}` in their own terminal"
        f"{prompt_note}. Do not try to approve it yourself.",
        {**data, "approval": {"status": "pending", "code": pending.code, "expires_in_seconds": remaining}},
        pending.code,
    )


def _gate_github_repo_reference(
    *,
    tool_name: str,
    arguments: Any,
    request_id: RequestId,
    audit_log_path: Path,
    repo_signatures: dict[str, SignatureList],
    fetch_tarball: FetchTarballFn,
    blocked: list[tuple[RequestId, str, int, dict | None]],
    audit_only: bool,
    trusted_repos: set[str] | None = None,
    approvals: ApprovalContext | None = None,
    is_call_approved: Callable[[], bool] | None = None,
) -> bool:
    """The optional GitHub repo scan (ARAN_SCAN_GITHUB_REPOS=1): if this call
    references a public GitHub repo, fetch and scan it before the call that
    would clone/download it is allowed through. Returns True if the call was
    dropped (appended to `blocked`), False otherwise.

    Four distinct outcomes, each logged differently:
      - no repo referenced: nothing to do, not logged (the overwhelming
        majority of calls; logging every one would just be audit noise for a
        feature this call never touched).
      - the repo is in the developer's personal trusted_repos allowlist
        (~/.aran/allowlist.yaml, see allowlist.py): the scan - and its
        network fetch - is skipped entirely, logged as "allowed" with
        detail noting why. This is the one thing in this function that
        actually saves latency, not just a permissive verdict after doing
        the work.
      - referenced but the scan itself failed (network error, timeout, repo
        not found, corrupt archive, ...): logged as "error" and the call is
        allowed through anyway. This is a deliberate fail-OPEN, unlike every
        other gate failure in this file - the thing that failed is a
        best-effort external lookup Aran does not control, not Aran's own
        ability to inspect a message it already has in hand. Blocking every
        clone whenever GitHub is unreachable or rate-limited would make this
        an opt-in feature that breaks normal use the moment the network
        hiccups, for a check that is inherently advisory (see repo_scan.py).
      - referenced and the scan completed and found something: logged as
        "blocked" (or "would_block" under audit_only) exactly like the
        destructive-command check above."""
    ref: GitHubRepoRef | None = find_github_repo_reference(tool_name, arguments)
    if ref is None:
        return False

    repo_label = f"{ref.owner}/{ref.repo}"

    if trusted_repos and is_trusted_repo(ref.owner, ref.repo, trusted_repos):
        log_event(
            audit_log_path,
            direction="outbound",
            tool_name=tool_name,
            outcome="allowed",
            matched_signature=None,
            detail={"repo": repo_label, "reason": "trusted_repos allowlist - scan skipped"},
        )
        return False

    result = scan_repo(ref.owner, ref.repo, signatures_by_category=repo_signatures, fetch_tarball=fetch_tarball)

    if result.error is not None:
        log_event(
            audit_log_path,
            direction="outbound",
            tool_name=tool_name,
            outcome="error",
            matched_signature=None,
            detail={"repo": repo_label, "reason": result.error},
        )
        _warn(f"[Aran] warning: GitHub repo scan for {repo_label} did not complete ({result.error}); forwarding without it")
        return False

    if not result.matches:
        log_event(
            audit_log_path,
            direction="outbound",
            tool_name=tool_name,
            outcome="allowed",
            matched_signature=None,
            detail={"repo": repo_label, "files_scanned": result.files_scanned},
        )
        return False

    first = result.matches[0]
    detail = {
        "repo": repo_label,
        "file": first.path,
        "category": first.category,
        "files_scanned": result.files_scanned,
    }
    if audit_only:
        log_event(
            audit_log_path,
            direction="outbound",
            tool_name=tool_name,
            outcome="would_block",
            matched_signature=first.matched_signature,
            detail=detail,
        )
        return False

    if is_call_approved is not None and is_call_approved():
        log_event(
            audit_log_path,
            direction="outbound",
            tool_name=tool_name,
            outcome="allowed",
            matched_signature=first.matched_signature,
            detail={**detail, "approved_by_user": True},
        )
        return False

    message_text = (
        f"[Aran] blocked: outbound call references GitHub repo {repo_label}, "
        f"which failed a content scan ({first.category}: {first.matched_signature!r} in {first.path!r})"
    )
    data = {
        "violation": "GitHub repo content scan matched",
        "repo": repo_label,
        "file": first.path,
        "category": first.category,
        "matched_signature": first.matched_signature,
    }
    message_text, data, code = _offer_approval(
        approvals,
        tool_name=tool_name,
        arguments=arguments,
        kind=KIND_REPO_SCAN,
        matched_signature=first.matched_signature,
        target_node=first.path,
        risk_detail=detail,
        message=message_text,
        data=data,
    )
    log_event(
        audit_log_path,
        direction="outbound",
        tool_name=tool_name,
        outcome="blocked",
        matched_signature=first.matched_signature,
        detail={**detail, "approval_code": code} if code else detail,
    )
    blocked.append((request_id, message_text, CODE_REPO_SCAN_BLOCKED, data))
    return True


def _gate_outbound_object(
    message: dict,
    *,
    output_signatures: SignatureList,
    audit_log_path: Path,
    pending_tool_calls: dict[RequestId, str],
    pending_lock: threading.Lock,
    blocked: list[tuple[RequestId, str, int, dict | None]],
    audit_only: bool = False,
    repo_scan_enabled: bool = False,
    repo_signatures: dict[str, SignatureList] | None = None,
    fetch_tarball: FetchTarballFn = default_fetch_tarball,
    pending_list_requests: set[RequestId] | None = None,
    answered: list[tuple[RequestId, str]] | None = None,
    pending_initialize_requests: set[RequestId] | None = None,
    trusted_repos: set[str] | None = None,
    loop_guard: LoopGuard | None = None,
    approvals: ApprovalContext | None = None,
) -> Any:
    """Gates one client->server JSON-RPC object. Returns the object to forward,
    or _DROP when the call is blocked - in which case (id, message, code, data)
    is appended to `blocked` so the caller can answer the client in the framing
    the client used. Also _DROP for a self-answered aran_status call, in which
    case (id, text) is appended to `answered` instead - same drop-and-answer
    shape, but a normal result rather than an error.

    In audit_only mode a match is logged as "would_block" but the call is
    still forwarded and registered exactly like a clean call - nothing is
    ever dropped while ARAN_MODE=audit. The same applies to a repo-scan match
    when repo_scan_enabled is on. aran_status is unaffected by audit_only -
    it never blocks anything itself, so there is nothing for that mode to
    disable."""
    if message.get("method") in ("tools/list", "initialize"):
        # Registered so the inbound side can splice Aran's own content into
        # the matching response when it comes back - aran_status into
        # tools/list, PROXY_INSTRUCTIONS into initialize's `instructions`.
        # Tracked the same bounded, insertion-order-agnostic way as
        # pending_tool_calls, because this is a discoverability nicety, not
        # a gating decision: losing a stale entry under load costs one
        # missed splice, never a security check.
        request_id = _usable_request_id(message.get("id"))
        target = pending_list_requests if message.get("method") == "tools/list" else pending_initialize_requests
        if target is not None:
            with pending_lock:
                target.add(request_id)
                while len(target) > _MAX_PENDING_TOOL_CALLS:
                    target.pop()
        return message

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

    if tool_name == STATUS_TOOL_NAME and answered is not None:
        # Answered here, unconditionally - never reaches check_output below,
        # never forwarded to the wrapped server. aran_status takes no
        # arguments that could plausibly match a destructive-command
        # signature, and even if some future argument shape did, this is
        # Aran's own reserved tool name: it would never make sense to block
        # a call to it.
        text = build_status_report(audit_log_path, arguments=arguments, audit_only=audit_only)
        log_event(
            audit_log_path,
            direction="outbound",
            tool_name=tool_name,
            outcome="allowed",
            matched_signature=None,
        )
        answered.append((request_id, text))
        return _DROP

    if tool_name == EXPLAIN_TOOL_NAME and answered is not None:
        # Same reasoning as aran_status above: this is a dry run against
        # the signature sets, never an actual gate decision, so it's
        # answered directly and skips check_output entirely - a `text`
        # argument crafted to look destructive is exactly what a developer
        # is supposed to be able to test here without tripping the real gate.
        text = build_explain_report(arguments, repo_signatures or {})
        log_event(
            audit_log_path,
            direction="outbound",
            tool_name=tool_name,
            outcome="allowed",
            matched_signature=None,
        )
        answered.append((request_id, text))
        return _DROP

    # Memoized so a one-time approval is claimed at most once per call, even
    # if both this check and the repo scan below would have blocked it.
    approval_result: list[bool] = []

    def call_approved() -> bool:
        if not approval_result:
            approval_result.append(_consume_approval(approvals, tool_name, arguments))
        return approval_result[0]

    matched = check_output(tool_name, arguments, output_signatures)
    if matched:
        if not audit_only and call_approved():
            # A human approved this exact call: forward it, say so in the audit
            # trail, and let the remaining checks (repo scan, loop guard) run.
            log_event(
                audit_log_path,
                direction="outbound",
                tool_name=tool_name,
                outcome="allowed",
                matched_signature=matched,
                detail={"approved_by_user": True},
            )
        elif not audit_only:
            target_node = locate_output_match(tool_name, arguments, matched)
            message_text = f"[Aran] blocked: outbound call matched signature {matched!r}"
            data = {
                "violation": "destructive command signature matched",
                "matched_signature": matched,
                "target_node": target_node,
            }
            message_text, data, code = _offer_approval(
                approvals,
                tool_name=tool_name,
                arguments=arguments,
                kind=KIND_SIGNATURE,
                matched_signature=matched,
                target_node=target_node,
                risk_detail=None,
                message=message_text,
                data=data,
            )
            log_event(
                audit_log_path,
                direction="outbound",
                tool_name=tool_name,
                outcome="blocked",
                matched_signature=matched,
                detail={"approval_code": code} if code else None,
            )
            blocked.append((request_id, message_text, CODE_SIGNATURE_BLOCKED, data))
            return _DROP
        else:
            # audit_only: log as "would_block" and fall through to the normal
            # allow path below - the call is still forwarded, unmodified.
            log_event(
                audit_log_path,
                direction="outbound",
                tool_name=tool_name,
                outcome="would_block",
                matched_signature=matched,
            )
    else:
        log_event(
            audit_log_path,
            direction="outbound",
            tool_name=tool_name,
            outcome="allowed",
            matched_signature=None,
        )

    if repo_scan_enabled:
        dropped = _gate_github_repo_reference(
            tool_name=tool_name,
            arguments=arguments,
            request_id=request_id,
            audit_log_path=audit_log_path,
            repo_signatures=repo_signatures or {},
            fetch_tarball=fetch_tarball,
            blocked=blocked,
            audit_only=audit_only,
            trusted_repos=trusted_repos,
            approvals=approvals,
            is_call_approved=call_approved,
        )
        if dropped:
            return _DROP

    if loop_guard is not None:
        count = loop_guard.record(tool_name, arguments)
        if loop_guard.would_block(count):
            message_text = (
                f"[Aran] blocked: {count} identical calls to {tool_name!r} "
                f"within {loop_guard.window_seconds:.0f}s - possible runaway loop"
            )
            data = {
                "violation": "repeated identical call - possible runaway loop",
                "tool_name": tool_name,
                "count": count,
                "window_seconds": loop_guard.window_seconds,
            }
            if not audit_only:
                log_event(
                    audit_log_path,
                    direction="outbound",
                    tool_name=tool_name,
                    outcome="blocked",
                    matched_signature=None,
                    detail=data,
                )
                blocked.append((request_id, message_text, CODE_LOOP_GUARD_BLOCKED, data))
                return _DROP
            log_event(
                audit_log_path,
                direction="outbound",
                tool_name=tool_name,
                outcome="would_block",
                matched_signature=None,
                detail=data,
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
    audit_only: bool = False,
    repo_scan_enabled: bool = False,
    repo_signatures: dict[str, SignatureList] | None = None,
    fetch_tarball: FetchTarballFn = default_fetch_tarball,
    pending_list_requests: set[RequestId] | None = None,
    pending_initialize_requests: set[RequestId] | None = None,
    trusted_repos: set[str] | None = None,
    loop_guard: LoopGuard | None = None,
    approvals: ApprovalContext | None = None,
) -> bytes | None:
    """Applies the output gate to one client->server line. Returns the bytes to
    forward to the server, or None if everything in the line was blocked (in
    which case the error response has already been written back to the client).

    In audit_only mode `blocked` is always empty (see _gate_outbound_object),
    so this always returns bytes to forward, never None."""
    try:
        message = _decode_json_line(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return line

    blocked: list[tuple[RequestId, str, int, dict | None]] = []
    answered: list[tuple[RequestId, str]] = []
    gated = _gate_outbound_value(
        message,
        output_signatures=output_signatures,
        audit_log_path=audit_log_path,
        pending_tool_calls=pending_tool_calls,
        pending_lock=pending_lock,
        blocked=blocked,
        audit_only=audit_only,
        repo_scan_enabled=repo_scan_enabled,
        repo_signatures=repo_signatures,
        fetch_tarball=fetch_tarball,
        pending_list_requests=pending_list_requests,
        answered=answered,
        pending_initialize_requests=pending_initialize_requests,
        trusted_repos=trusted_repos,
        loop_guard=loop_guard,
        approvals=approvals,
    )

    if blocked:
        # Every blocked call the client can be answered for gets an error for
        # its own id, in the framing it was sent in: one object for a plain
        # request, an array for a batch. A blocked element with no usable id is
        # a notification - there is nothing to answer.
        payloads = [
            _blocked_payload(rid, text, code=code, data=data)
            for rid, text, code, data in blocked
            if rid is not None
        ]
        if payloads:
            _write_line(
                client_out,
                client_out_lock,
                _encode_json_line(payloads if isinstance(message, list) else payloads[0]),
            )

    if answered:
        # Same shape as the `blocked` write above, kept as a separate
        # message: aran_status is answered with a *result*, not an *error*,
        # so it can't share _blocked_payload's error-shaped construction.
        status_payloads = [_status_payload(rid, text) for rid, text in answered if rid is not None]
        if status_payloads:
            _write_line(
                client_out,
                client_out_lock,
                _encode_json_line(status_payloads if isinstance(message, list) else status_payloads[0]),
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
    audit_only: bool = False,
    profile: bool = False,
    repo_scan_enabled: bool = False,
    repo_signatures: dict[str, SignatureList] | None = None,
    fetch_tarball: FetchTarballFn = default_fetch_tarball,
    pending_list_requests: set[RequestId] | None = None,
    pending_initialize_requests: set[RequestId] | None = None,
    trusted_repos: set[str] | None = None,
    loop_guard: LoopGuard | None = None,
    approvals: ApprovalContext | None = None,
) -> None:
    try:
        while True:
            line = client_in.readline()
            if not line:
                break
            try:
                start = time.perf_counter_ns() if profile else 0
                forward = _gate_outbound_message(
                    line,
                    output_signatures=output_signatures,
                    audit_log_path=audit_log_path,
                    pending_tool_calls=pending_tool_calls,
                    pending_lock=pending_lock,
                    client_out=client_out,
                    client_out_lock=client_out_lock,
                    audit_only=audit_only,
                    repo_scan_enabled=repo_scan_enabled,
                    repo_signatures=repo_signatures,
                    fetch_tarball=fetch_tarball,
                    pending_list_requests=pending_list_requests,
                    pending_initialize_requests=pending_initialize_requests,
                    trusted_repos=trusted_repos,
                    loop_guard=loop_guard,
                    approvals=approvals,
                )
                if profile:
                    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                    _warn(
                        f"[Aran Profiler] Checked outbound call against "
                        f"{len(output_signatures)} signatures in {elapsed_ms:.2f}ms"
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


def _inject_status_tool_listing(message: dict) -> None:
    """Splices aran_status's and aran_explain's definitions into a
    tools/list response's result.tools, so an agent can discover and call
    them the normal way instead of only when a developer names one
    exactly. Best-effort and silent: a result that isn't a dict, or has no
    `tools` list, isn't the shape this expects - left alone rather than
    forced into that shape, the same "don't fabricate structure the server
    didn't send" stance locate_output_match and the repo scan already take
    elsewhere."""
    result = message.get("result")
    if not isinstance(result, dict):
        return
    tools = result.get("tools")
    if not isinstance(tools, list):
        return
    existing_names = {t.get("name") for t in tools if isinstance(t, dict)}
    for definition in (STATUS_TOOL_DEFINITION, EXPLAIN_TOOL_DEFINITION):
        if definition["name"] in existing_names:
            continue  # already present - a hostile/unusual server claiming the name, or a re-spliced id
        tools.append(dict(definition))


def _inject_proxy_instructions(message: dict) -> None:
    """Appends PROXY_INSTRUCTIONS to an initialize response's
    result.instructions, so the agent learns what a blocked-call error or a
    redaction notice means at session start - before it can possibly hit
    either - instead of only if a developer happens to ask. Appends rather
    than replaces: a real server's own instructions (if any) are content
    the agent still needs, not something Aran gets to discard."""
    result = message.get("result")
    if not isinstance(result, dict):
        return
    existing = result.get("instructions")
    if isinstance(existing, str) and PROXY_INSTRUCTIONS in existing:
        return  # already present - re-spliced id or a server that echoes it back
    if isinstance(existing, str) and existing.strip():
        result["instructions"] = existing + "\n\n" + PROXY_INSTRUCTIONS
    else:
        result["instructions"] = PROXY_INSTRUCTIONS


def _gate_response_object(
    message: dict,
    *,
    input_signatures: SignatureList,
    audit_log_path: Path,
    pending_tool_calls: dict[RequestId, str],
    pending_lock: threading.Lock,
    audit_only: bool = False,
    leaf_count: list[int] | None = None,
    pending_list_requests: set[RequestId] | None = None,
    pending_initialize_requests: set[RequestId] | None = None,
) -> None:
    """Gates one response-shaped JSON-RPC object in place, and audits it.

    In audit_only mode, `message` is left completely unmodified - see
    _scan_and_redact - but `redactions` is still populated with what WOULD
    have been redacted, so the audit outcome below can say "would_block"."""
    request_id = _usable_request_id(message.get("id"))
    with pending_lock:
        tool_name = pending_tool_calls.get(request_id)
        is_list_response = pending_list_requests is not None and request_id in pending_list_requests
        is_initialize_response = (
            pending_initialize_requests is not None and request_id in pending_initialize_requests
        )

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
                audit_only=audit_only,
                leaf_count=leaf_count,
            )

    if is_list_response:
        # After scanning, not before: this is Aran's own trusted text, not
        # something that arrived from the (untrusted) wrapped server, so it
        # has no business going through the input gate at all.
        _inject_status_tool_listing(message)
    if is_initialize_response:
        _inject_proxy_instructions(message)

    if redactions:
        outcome = "would_block" if audit_only else "blocked"
    else:
        outcome = "allowed"
    log_event(
        audit_log_path,
        direction="inbound",
        tool_name=tool_name,
        # "blocked"/"would_block" means content was (or, in audit mode, would
        # have been) rewritten. A match in an exempt machinery field
        # (protocolVersion, tool name, resource uri, ... - see
        # _rewrite_allowed) is still named in the record for false-positive
        # tuning, but the message was relayed as it arrived either way.
        outcome=outcome,
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
    audit_only: bool = False,
    leaf_count: list[int] | None = None,
    pending_list_requests: set[RequestId] | None = None,
    pending_initialize_requests: set[RequestId] | None = None,
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
        audit_only=audit_only,
        leaf_count=leaf_count,
        pending_list_requests=pending_list_requests,
        pending_initialize_requests=pending_initialize_requests,
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
    audit_only: bool = False,
    profile: bool = False,
    pending_list_requests: set[RequestId] | None = None,
    pending_initialize_requests: set[RequestId] | None = None,
) -> None:
    try:
        while True:
            line = server_out.readline()
            if not line:
                break
            try:
                leaf_count = [0] if profile else None
                start = time.perf_counter_ns() if profile else 0
                out_line = _gate_inbound_message(
                    line,
                    input_signatures=input_signatures,
                    audit_log_path=audit_log_path,
                    pending_tool_calls=pending_tool_calls,
                    pending_lock=pending_lock,
                    audit_only=audit_only,
                    leaf_count=leaf_count,
                    pending_list_requests=pending_list_requests,
                    pending_initialize_requests=pending_initialize_requests,
                )
                if profile:
                    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                    _warn(
                        f"[Aran Profiler] Audited {leaf_count[0]} JSON leaf nodes "
                        f"against {len(input_signatures)} signatures in {elapsed_ms:.2f}ms"
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
    audit_only: bool = False,
    profile: bool = False,
    scan_github_repos: bool = False,
    secret_signatures: SignatureList = (),
    supply_chain_signatures: SignatureList = (),
    fetch_tarball: FetchTarballFn = default_fetch_tarball,
    trusted_repos: set[str] | None = None,
    loop_guard_enabled: bool = False,
    loop_guard_threshold: int = DEFAULT_THRESHOLD,
    loop_guard_window_seconds: float = DEFAULT_WINDOW_SECONDS,
    approvals: ApprovalContext | None = None,
) -> int:
    """Spawns `command` as the real MCP server and relays JSON-RPC between
    client_in/client_out (the IDE side) and the child's stdio, applying the
    output gate to outbound tools/call requests and the input gate to every
    inbound JSON-RPC response. Returns the child process's exit code, or
    EXIT_PROXY_DEGRADED if the relay itself failed while the child exited 0.

    Signatures are compiled once here rather than per string leaf: the input
    gate now runs over every leaf of every response, so re-resolving ~200
    patterns through re.search() per leaf cost seconds on a large payload and
    made the single-threaded inbound relay look like a hang (N3).

    audit_only=True (ARAN_MODE=audit) disables blocking/redaction entirely:
    every match is logged as "would_block" instead, and the original call or
    content is always forwarded unmodified. profile=True (ARAN_PROFILE=1)
    prints a timing/signature-count line to stderr for every gated message -
    both are independent, off-by-default toggles read from the environment
    by cli.py, not something a downstream server can turn on itself.

    scan_github_repos=True (ARAN_SCAN_GITHUB_REPOS=1) additionally scans any
    public GitHub repo referenced in an outbound tool call's arguments
    (destructive commands, prompt injection, hardcoded secrets, and
    supply-chain install/build hooks - see repo_scan.py) before the call
    that would clone/download it is forwarded. Unlike every other check in
    this file it makes real network requests, which is why it defaults off;
    `secret_signatures`/`supply_chain_signatures` are the two rule
    categories specific to that scan, and `fetch_tarball` is overridable
    only for tests - callers outside this module should never need it.

    Always on, unconditionally: the aran_status meta-tool (status.py) - a
    developer can ask their agent for it directly and get a live summary
    of what this session has gated, without opening the audit log
    themselves. It's read-only, makes no network calls, and changes no
    gating decision, so unlike the toggles above it needs no opt-in. Also
    always on: PROXY_INSTRUCTIONS is spliced into the initialize response's
    `instructions` field, so the agent learns what a blocked-call error or
    a redaction notice means at session start, before it can hit either -
    the actual answer to "can the agent respond faster": zero extra round
    trips, because the context is already there the first time it matters.

    loop_guard_enabled=True (ARAN_LOOP_GUARD=1) blocks a tool call once the
    same call (same name, same arguments) has repeated
    loop_guard_threshold times within loop_guard_window_seconds - a
    frequency-based check, not content-based, for a stuck/looping agent
    hammering an otherwise-benign call. Off by default: unlike every
    content-based check in this file, a fast legitimate repeat (polling,
    an intentional retry) looks identical to a genuine loop by design, so
    this is opt-in the same way the GitHub repo scan is, for a different
    reason (see loop_guard.py).

    approvals (see approvals.py) turns a signature/repo-scan block into
    "blocked, awaiting a human": the call is still blocked, but parked under
    a code a person can approve (terminal command or desktop dialog - never
    the agent), after which a retry of that exact call passes. None means
    plain blocking, exactly as before."""
    compiled_input = compile_signatures(input_signatures)
    compiled_output = compile_signatures(output_signatures)
    repo_signatures = {
        "destructive_command": compiled_output,
        "prompt_injection": compiled_input,
        "secret": compile_signatures(secret_signatures),
        "supply_chain": compile_signatures(supply_chain_signatures),
    }
    loop_guard = (
        LoopGuard(threshold=loop_guard_threshold, window_seconds=loop_guard_window_seconds)
        if loop_guard_enabled
        else None
    )

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
    pending_list_requests: set[RequestId] = set()
    pending_initialize_requests: set[RequestId] = set()
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
                audit_only=audit_only,
                profile=profile,
                repo_scan_enabled=scan_github_repos,
                repo_signatures=repo_signatures,
                fetch_tarball=fetch_tarball,
                pending_list_requests=pending_list_requests,
                pending_initialize_requests=pending_initialize_requests,
                trusted_repos=trusted_repos,
                loop_guard=loop_guard,
                approvals=approvals,
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
                audit_only=audit_only,
                profile=profile,
                pending_list_requests=pending_list_requests,
                pending_initialize_requests=pending_initialize_requests,
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
