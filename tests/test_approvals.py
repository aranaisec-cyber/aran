import json
from pathlib import Path

import pytest
import yaml

from aran import cli
from aran.approvals import (
    CODE_PREFIX,
    KIND_REPO_SCAN,
    KIND_SIGNATURE,
    ApprovalError,
    ApprovalStore,
    call_key,
    describe_risk,
    format_review,
    normalize_code,
)


class FakeClock:
    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store(tmp_path: Path, clock: FakeClock) -> ApprovalStore:
    return ApprovalStore(tmp_path / "approvals", audit_log_path=tmp_path / "audit.jsonl", clock=clock)


def _pend(store: ApprovalStore, arguments=None, tool_name="run_command"):
    arguments = {"command": "rm -rf /tmp/x"} if arguments is None else arguments
    return store.get_or_create_pending(
        call_key(tool_name, arguments),
        tool_name=tool_name,
        arguments=arguments,
        kind=KIND_SIGNATURE,
        matched_signature=r"rm\s+-[rfRF]+",
        target_node="arguments.command",
        risk="risky",
    )


# --- call_key ---------------------------------------------------------------

def test_call_key_is_stable_and_argument_order_independent():
    assert call_key("t", {"a": 1, "b": 2}) == call_key("t", {"b": 2, "a": 1})


def test_call_key_distinguishes_tool_and_arguments():
    assert call_key("t", {"a": 1}) != call_key("t", {"a": 2})
    assert call_key("t", {"a": 1}) != call_key("u", {"a": 1})


def test_call_key_tolerates_unserializable_arguments():
    assert len(call_key("t", {"x": object()})) == 64


# --- pending ------------------------------------------------------------------

def test_new_pending_gets_a_human_friendly_code(store):
    pending, created = _pend(store)

    assert created is True
    assert pending.code.startswith(CODE_PREFIX)
    assert len(pending.code) == len(CODE_PREFIX) + 6
    assert not set(pending.code[len(CODE_PREFIX):]) & set("01OIL")


def test_the_same_call_reuses_its_pending_entry(store):
    first, created_first = _pend(store)
    second, created_second = _pend(store)

    assert (created_first, created_second) == (True, False)
    assert second.code == first.code
    assert len(store.list_pending()) == 1


def test_different_calls_get_different_codes(store):
    a, _ = _pend(store, {"command": "rm -rf /a"})
    b, _ = _pend(store, {"command": "rm -rf /b"})

    assert a.code != b.code
    assert len(store.list_pending()) == 2


def test_pending_expires(store, clock):
    pending, _ = _pend(store)

    clock.now += store.pending_ttl + 1

    assert store.get_pending(pending.code) is None
    assert store.list_pending() == []


def test_an_expired_pending_is_replaced_by_a_fresh_one(store, clock):
    old, _ = _pend(store)
    clock.now += store.pending_ttl + 1

    new, created = _pend(store)

    assert created is True
    assert new.code != old.code


def test_preview_is_truncated_but_the_total_length_is_recorded(store):
    big = {"command": "rm -rf /" + "x" * 5000}
    pending, _ = _pend(store, big)

    assert len(pending.preview) < 2000
    assert pending.args_chars > 5000
    assert "only the first" in format_review(pending)


def test_code_lookup_ignores_case_and_a_missing_prefix(store):
    pending, _ = _pend(store)
    bare = pending.code[len(CODE_PREFIX):].lower()

    assert normalize_code(bare) == pending.code
    assert store.get_pending(bare) is not None


# --- approve / consume ----------------------------------------------------------

def test_approved_call_is_consumed_as_approved_and_remembered(store):
    pending, _ = _pend(store)
    key = pending.key

    store.approve(pending.code)

    assert store.status(key) == "approved"
    assert store.consume_approval(key) is True
    assert store.consume_approval(key) is True  # remembered, not single-use
    assert store.get_pending(pending.code) is None


def test_one_time_approval_works_once_then_is_gone(store):
    pending, _ = _pend(store)
    store.approve(pending.code, once=True)

    assert store.consume_approval(pending.key) is True
    assert store.consume_approval(pending.key) is False
    assert store.status(pending.key) is None


def test_an_unapproved_call_is_not_approved(store):
    assert store.consume_approval(call_key("t", {"a": 1})) is False


def test_approval_covers_only_the_exact_call(store):
    pending, _ = _pend(store, {"command": "rm -rf /a"})
    store.approve(pending.code)

    assert store.consume_approval(call_key("run_command", {"command": "rm -rf /b"})) is False


def test_approving_an_unknown_code_raises(store):
    with pytest.raises(ApprovalError):
        store.approve("AR-ZZZZZZ")


def test_approving_twice_raises_the_second_time(store):
    pending, _ = _pend(store)
    store.approve(pending.code)

    with pytest.raises(ApprovalError):
        store.approve(pending.code)


def test_cannot_approve_an_expired_request(store, clock):
    pending, _ = _pend(store)
    clock.now += store.pending_ttl + 1

    with pytest.raises(ApprovalError):
        store.approve(pending.code)


# --- decline -----------------------------------------------------------------------

def test_declined_call_is_remembered_and_never_approved(store):
    pending, _ = _pend(store)
    store.decline(pending.code)

    assert store.status(pending.key) == "declined"
    assert store.consume_approval(pending.key) is False


def test_a_later_approval_overrides_an_earlier_decline(store):
    first, _ = _pend(store)
    store.decline(first.code)
    assert store.status(first.key) == "declined"
    # the gate won't create a pending entry for a declined call, but the store
    # itself doesn't forbid one - e.g. a human deciding to reverse themselves
    second, created = _pend(store)
    store.approve(second.code)

    assert created is True
    assert store.status(first.key) == "approved"
    assert store.list_decisions()[1] == []


# --- revoke / list -------------------------------------------------------------------

def test_revoke_forgets_an_approval_by_key_prefix(store):
    pending, _ = _pend(store)
    store.approve(pending.code)

    assert store.revoke(pending.key[:8]) == 1
    assert store.consume_approval(pending.key) is False


def test_revoke_cancels_a_pending_request_by_code(store):
    pending, _ = _pend(store)

    assert store.revoke(pending.code) == 1
    assert store.list_pending() == []


def test_revoke_requires_enough_characters_to_be_unambiguous(store):
    with pytest.raises(ApprovalError):
        store.revoke("ab")


def test_revoke_with_no_match_removes_nothing(store):
    assert store.revoke("deadbeefcafe") == 0


def test_list_decisions_separates_approved_from_declined(store):
    a, _ = _pend(store, {"command": "rm -rf /a"})
    b, _ = _pend(store, {"command": "rm -rf /b"})
    store.approve(a.code)
    store.decline(b.code)

    approved, declined = store.list_decisions()

    assert [d["key"] for d in approved] == [a.key]
    assert [d["key"] for d in declined] == [b.key]


# --- audit trail ----------------------------------------------------------------------

def test_decisions_are_written_to_the_audit_log(store, tmp_path):
    a, _ = _pend(store, {"command": "rm -rf /a"})
    b, _ = _pend(store, {"command": "rm -rf /b"})
    store.approve(a.code, once=True, via="dialog")
    store.decline(b.code, via="cli")
    store.revoke(a.key[:8])  # the one-time approval was never used, so it's still on disk

    events = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    approval_events = [e for e in events if e["direction"] == "approval"]

    assert [e["outcome"] for e in approval_events] == ["approved", "declined", "revoked"]
    assert approval_events[0]["detail"]["via"] == "dialog"
    assert approval_events[0]["detail"]["once"] is True
    assert approval_events[1]["detail"]["via"] == "cli"


def test_store_without_an_audit_path_still_works(tmp_path, clock):
    quiet = ApprovalStore(tmp_path / "a", clock=clock)
    pending, _ = _pend(quiet)

    quiet.approve(pending.code)

    assert quiet.status(pending.key) == "approved"


# --- risk text ----------------------------------------------------------------------------

def test_every_shipped_output_signature_has_a_specific_risk_description():
    """A new destructive signature in default-rules.yaml should come with a
    plain-language risk line - otherwise a human approving it only ever sees
    the generic fallback."""
    with open(cli.DEFAULT_RULES_PATH, encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    generic = describe_risk(KIND_SIGNATURE, None)

    missing = [s for s in rules["output_gate_signatures"] if describe_risk(KIND_SIGNATURE, s) == generic]

    assert missing == []


def test_unknown_signature_falls_back_to_a_generic_description():
    assert "review the arguments" in describe_risk(KIND_SIGNATURE, "something custom")


def test_repo_scan_risk_names_the_repo_file_and_category():
    text = describe_risk(KIND_REPO_SCAN, "AKIA", {"repo": "o/r", "file": "x.py", "category": "secret"})

    assert "o/r" in text and "x.py" in text and "credential" in text


def test_format_review_shows_tool_risk_match_and_arguments(store):
    pending, _ = _pend(store)

    text = format_review(pending)

    assert "run_command" in text
    assert "risky" in text
    assert r"rm\s+-[rfRF]+" in text
    assert "arguments.command" in text
    assert "rm -rf /tmp/x" in text
    assert pending.code in text
