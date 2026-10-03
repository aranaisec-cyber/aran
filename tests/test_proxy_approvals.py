import io
import json
import tarfile
from pathlib import Path

import pytest

from aran.approvals import ApprovalContext, ApprovalStore
from aran.proxy import run_proxy

RM = r"rm\s+-[rfRF]+"


def _bytes(messages):
    return io.BytesIO("".join(json.dumps(m) + "\n" for m in messages).encode("utf-8"))


def _responses(buf):
    return {r["id"]: r for r in (json.loads(l) for l in buf.getvalue().decode("utf-8").splitlines() if l.strip())}


def _call(request_id, command="rm -rf /tmp/x", tool="run_command"):
    return {
        "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
        "params": {"name": tool, "arguments": {"command": command}},
    }


@pytest.fixture
def store(tmp_path: Path) -> ApprovalStore:
    return ApprovalStore(tmp_path / "approvals", audit_log_path=tmp_path / "audit.jsonl")


def _run(fake_server_command, tmp_path, store, messages, *, notify=None, **kwargs):
    out = io.BytesIO()
    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[RM],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=_bytes(messages),
        client_out=out,
        approvals=ApprovalContext(store, notify),
        **kwargs,
    )
    assert code == 0
    return _responses(out)


def _audit(tmp_path):
    return [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]


# --- the block becomes "awaiting a human" ---------------------------------------

def test_a_blocked_call_carries_an_approval_code_and_stays_blocked(fake_server_command, tmp_path, store):
    responses = _run(fake_server_command, tmp_path, store, [_call(1)])

    error = responses[1]["error"]
    code = error["data"]["approval"]["code"]
    assert error["code"] == -32001  # still a block, same code as ever
    assert error["data"]["approval"]["status"] == "pending"
    assert code in error["message"]
    assert f"aran approve {code}" in error["message"]
    assert "Do not try to approve it yourself" in error["message"]
    assert "ran run_command" not in json.dumps(responses)  # never reached the server
    assert store.get_pending(code) is not None


def test_the_agent_visible_message_does_not_echo_the_arguments(fake_server_command, tmp_path, store):
    """Arguments are attacker-controlled (that's the threat model) and the
    agent reads this message - only Aran's own text and a code go in it."""
    responses = _run(fake_server_command, tmp_path, store, [_call(1, "rm -rf /tmp/SECRET_MARKER_123")])

    assert "SECRET_MARKER_123" not in json.dumps(responses[1]["error"])


def test_a_retried_blocked_call_reuses_one_code_and_notifies_once(fake_server_command, tmp_path, store):
    notified = []

    responses = _run(fake_server_command, tmp_path, store, [_call(1), _call(2)], notify=notified.append)

    assert responses[1]["error"]["data"]["approval"]["code"] == responses[2]["error"]["data"]["approval"]["code"]
    assert len(notified) == 1
    assert len(store.list_pending()) == 1


def test_notify_receives_the_pending_request_to_show_the_human(fake_server_command, tmp_path, store):
    notified = []

    _run(fake_server_command, tmp_path, store, [_call(1)], notify=notified.append)

    assert notified[0].tool_name == "run_command"
    assert "rm -rf /tmp/x" in notified[0].preview
    assert "Deletes files" in notified[0].risk


def test_the_block_audit_entry_records_the_code(fake_server_command, tmp_path, store):
    responses = _run(fake_server_command, tmp_path, store, [_call(1)])

    blocked = [e for e in _audit(tmp_path) if e["outcome"] == "blocked"]
    assert blocked[0]["detail"]["approval_code"] == responses[1]["error"]["data"]["approval"]["code"]


# --- approve, then retry ----------------------------------------------------------

def test_an_approved_call_passes_on_retry(fake_server_command, tmp_path, store):
    first = _run(fake_server_command, tmp_path, store, [_call(1)])
    store.approve(first[1]["error"]["data"]["approval"]["code"])

    second = _run(fake_server_command, tmp_path, store, [_call(2)])

    assert "error" not in second[2]
    assert second[2]["result"]["content"][0]["text"] == "ran run_command"  # reached the real server


def test_approval_is_remembered_across_later_sessions(fake_server_command, tmp_path, store):
    first = _run(fake_server_command, tmp_path, store, [_call(1)])
    store.approve(first[1]["error"]["data"]["approval"]["code"])

    for request_id in (2, 3):  # two separate proxy sessions
        responses = _run(fake_server_command, tmp_path, store, [_call(request_id)])
        assert "error" not in responses[request_id]


def test_the_approved_pass_is_audited_as_allowed_by_the_user(fake_server_command, tmp_path, store):
    first = _run(fake_server_command, tmp_path, store, [_call(1)])
    store.approve(first[1]["error"]["data"]["approval"]["code"])

    _run(fake_server_command, tmp_path, store, [_call(2)])

    passed = [e for e in _audit(tmp_path) if e.get("detail", {}).get("approved_by_user")]
    assert len(passed) == 1
    assert passed[0]["outcome"] == "allowed"
    assert passed[0]["matched_signature"] == RM  # the log still says what it would have matched


def test_approving_one_call_does_not_approve_a_different_one(fake_server_command, tmp_path, store):
    first = _run(fake_server_command, tmp_path, store, [_call(1, "rm -rf /tmp/a")])
    store.approve(first[1]["error"]["data"]["approval"]["code"])

    second = _run(fake_server_command, tmp_path, store, [_call(2, "rm -rf /tmp/b")])

    assert second[2]["error"]["code"] == -32001
    assert second[2]["error"]["data"]["approval"]["status"] == "pending"


def test_a_one_time_approval_is_used_up_by_the_first_retry(fake_server_command, tmp_path, store):
    first = _run(fake_server_command, tmp_path, store, [_call(1)])
    store.approve(first[1]["error"]["data"]["approval"]["code"], once=True)

    # two identical calls in one session: only the first can use the approval
    second = _run(fake_server_command, tmp_path, store, [_call(2), _call(3)])

    outcomes = sorted("error" in second[i] for i in (2, 3))
    assert outcomes == [False, True]


def test_an_approval_never_unblocks_the_loop_guard(fake_server_command, tmp_path, store):
    """Approvals are for content blocks (-32001/-32002); a runaway loop of an
    approved call must still trip the guard."""
    first = _run(fake_server_command, tmp_path, store, [_call(1)])
    store.approve(first[1]["error"]["data"]["approval"]["code"])

    responses = _run(
        fake_server_command, tmp_path, store, [_call(i) for i in range(2, 6)],
        loop_guard_enabled=True, loop_guard_threshold=3,
    )

    assert any(r.get("error", {}).get("code") == -32003 for r in responses.values())


# --- decline -------------------------------------------------------------------------

def test_a_declined_call_stays_blocked_and_is_not_asked_about_again(fake_server_command, tmp_path, store):
    first = _run(fake_server_command, tmp_path, store, [_call(1)])
    store.decline(first[1]["error"]["data"]["approval"]["code"])
    notified = []

    second = _run(fake_server_command, tmp_path, store, [_call(2)], notify=notified.append)

    error = second[2]["error"]
    assert error["code"] == -32001
    assert error["data"]["approval"] == {"status": "declined"}
    assert "previously declined" in error["message"]
    assert notified == []
    assert store.list_pending() == []


# --- approvals off / unavailable -------------------------------------------------------

def test_without_approvals_a_block_is_exactly_the_plain_block(fake_server_command, tmp_path):
    out = io.BytesIO()
    run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[RM],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=_bytes([_call(1)]), client_out=out,
    )

    error = _responses(out)[1]["error"]
    assert set(error["data"]) == {"violation", "matched_signature", "target_node"}
    assert "approval" not in error["message"].lower()


def test_audit_only_mode_never_creates_approval_requests(fake_server_command, tmp_path, store):
    responses = _run(fake_server_command, tmp_path, store, [_call(1)], audit_only=True)

    assert "error" not in responses[1]
    assert store.list_pending() == []


def test_an_unwritable_store_leaves_the_call_blocked(fake_server_command, tmp_path, capsys):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("a file where the approvals directory should be", encoding="utf-8")
    broken = ApprovalStore(blocker / "approvals", audit_log_path=tmp_path / "audit.jsonl")

    responses = _run(fake_server_command, tmp_path, broken, [_call(1)])

    assert responses[1]["error"]["code"] == -32001  # fail closed
    assert "approval" not in responses[1]["error"]["data"]
    assert "could not record an approval request" in capsys.readouterr().err


def test_the_agent_has_no_tool_to_approve_with(fake_server_command, tmp_path, store):
    """There is deliberately no aran_approve: any channel the agent can reach,
    a prompt injection can reach. A tools/call for one is just forwarded to
    the wrapped server like any unknown tool - it approves nothing."""
    first = _run(fake_server_command, tmp_path, store, [_call(1)])
    code = first[1]["error"]["data"]["approval"]["code"]

    attempt = {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "aran_approve", "arguments": {"code": code}},
    }
    responses = _run(fake_server_command, tmp_path, store, [attempt, _call(3)])

    assert responses[2]["result"]["content"][0]["text"] == "ran aran_approve"  # forwarded, ignored
    assert responses[3]["error"]["code"] == -32001  # still blocked
    assert store.get_pending(code) is not None


# --- repo scan --------------------------------------------------------------------------

def _tarball(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in files.items():
            info = tarfile.TarInfo(name=f"demo-main/{path}")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


CLONE = {
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "run_command", "arguments": {"command": "git clone https://github.com/octocat/demo"}},
}


def test_a_repo_scan_block_can_be_approved_and_retried(fake_server_command, tmp_path, store):
    tarball = _tarball({"install.sh": b"rm -rf /\n"})
    kwargs = dict(scan_github_repos=True, fetch_tarball=lambda o, r, ref: tarball)

    first = _run(fake_server_command, tmp_path, store, [CLONE], **kwargs)
    error = first[1]["error"]
    assert error["code"] == -32002
    assert error["data"]["approval"]["status"] == "pending"
    store.approve(error["data"]["approval"]["code"])

    second = _run(fake_server_command, tmp_path, store, [{**CLONE, "id": 2}], **kwargs)

    assert "error" not in second[2]
    passed = [e for e in _audit(tmp_path) if e.get("detail", {}).get("approved_by_user")]
    assert passed and passed[-1]["detail"]["repo"] == "octocat/demo"


def test_one_time_approval_covers_both_checks_without_being_used_twice(fake_server_command, tmp_path, store):
    """A call that trips BOTH the destructive-command signature and the repo
    scan must be unblocked by a single one-time approval, not need two."""
    tarball = _tarball({"install.sh": b"rm -rf /\n"})
    call = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "run_command", "arguments": {"command": "rm -rf /tmp/x && git clone https://github.com/octocat/demo"}},
    }
    kwargs = dict(scan_github_repos=True, fetch_tarball=lambda o, r, ref: tarball)
    first = _run(fake_server_command, tmp_path, store, [call], **kwargs)
    store.approve(first[1]["error"]["data"]["approval"]["code"], once=True)

    second = _run(fake_server_command, tmp_path, store, [{**call, "id": 2}], **kwargs)

    assert "error" not in second[2]


def test_the_message_only_mentions_a_desktop_prompt_when_one_exists(fake_server_command, tmp_path, store):
    without = _run(fake_server_command, tmp_path, store, [_call(1)])[1]["error"]["message"]
    with_prompt = _run(fake_server_command, tmp_path, store, [_call(2, "rm -rf /tmp/y")], notify=lambda p: None)[2]["error"]["message"]

    assert "desktop prompt" not in without
    assert "desktop prompt" in with_prompt
