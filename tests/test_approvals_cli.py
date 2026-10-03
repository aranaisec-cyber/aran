import io
from pathlib import Path

import pytest

from aran import approvals_cli, cli
from aran.approvals import KIND_SIGNATURE, ApprovalStore, call_key


@pytest.fixture
def store(tmp_path: Path) -> ApprovalStore:
    return ApprovalStore(tmp_path / "approvals", audit_log_path=tmp_path / "audit.jsonl")


def _pend(store: ApprovalStore, command="rm -rf /tmp/x"):
    args = {"command": command}
    pending, _ = store.get_or_create_pending(
        call_key("run_command", args),
        tool_name="run_command",
        arguments=args,
        kind=KIND_SIGNATURE,
        matched_signature=r"rm\s+-[rfRF]+",
        target_node="arguments.command",
        risk="Deletes things.",
    )
    return pending


def _run(store, argv, *, answer="y", interactive=True):
    out = io.StringIO()
    asked = []

    def fake_input(prompt):
        asked.append(prompt)
        return answer

    code = approvals_cli.run(argv, store=store, out=out, input_fn=fake_input, is_interactive=lambda: interactive)
    return code, out.getvalue(), asked


# --- list --------------------------------------------------------------------

def test_list_when_empty(store):
    code, text, _ = _run(store, ["approvals"])
    assert code == 0 and "No pending requests" in text


def test_list_shows_pending_with_code_tool_and_risk(store):
    pending = _pend(store)

    code, text, _ = _run(store, ["approvals"])

    assert code == 0
    assert pending.code in text and "run_command" in text and "Deletes things." in text
    assert "aran approve CODE" in text


def test_list_shows_remembered_decisions(store):
    a = _pend(store, "rm -rf /a")
    b = _pend(store, "rm -rf /b")
    store.approve(a.code)
    store.decline(b.code)

    _, text, _ = _run(store, ["approvals", "list"])

    assert "Remembered approvals" in text and a.key[:10] in text
    assert "Remembered declines" in text and b.key[:10] in text


# --- approve -------------------------------------------------------------------

def test_approve_shows_the_risk_asks_and_records_on_yes(store):
    pending = _pend(store)

    code, text, asked = _run(store, ["approve", pending.code], answer="y")

    assert code == 0
    assert "Deletes things." in text and "rm -rf /tmp/x" in text  # reviewed before deciding
    assert len(asked) == 1
    assert store.consume_approval(pending.key) is True


@pytest.mark.parametrize("answer", ["", "n", "no", "maybe", "  "])
def test_approve_without_an_explicit_yes_records_nothing(store, answer):
    pending = _pend(store)

    code, text, _ = _run(store, ["approve", pending.code], answer=answer)

    assert code == 1
    assert "no decision recorded" in text
    assert store.status(pending.key) is None
    assert store.get_pending(pending.code) is not None


def test_approve_once_is_single_use(store):
    pending = _pend(store)

    code, text, asked = _run(store, ["approve", pending.code, "--once"])

    assert code == 0 and "one time" in text and "one time only" in asked[0]
    assert store.consume_approval(pending.key) is True
    assert store.consume_approval(pending.key) is False


def test_approve_refuses_without_an_interactive_terminal(store):
    """The load-bearing property: an agent's non-interactive shell tool must
    not be able to approve its own blocked call."""
    pending = _pend(store)

    code, text, asked = _run(store, ["approve", pending.code], interactive=False)

    assert code == 1
    assert "interactive terminal" in text
    assert asked == []  # never even prompted
    assert store.status(pending.key) is None


def test_approve_unknown_code(store):
    code, text, _ = _run(store, ["approve", "AR-NOPE00"])
    assert code == 1 and "no pending approval" in text


def test_approve_requires_exactly_one_code(store):
    code, text, _ = _run(store, ["approve"])
    assert code == 2 and "usage" in text


# --- decline / revoke -----------------------------------------------------------

def test_decline_records_without_needing_a_terminal(store):
    pending = _pend(store)

    code, text, asked = _run(store, ["decline", pending.code], interactive=False)

    assert code == 0 and "will not ask" in text and asked == []
    assert store.status(pending.key) == "declined"


def test_revoke_removes_a_remembered_approval(store):
    pending = _pend(store)
    store.approve(pending.code)

    code, text, _ = _run(store, ["approvals", "revoke", pending.key[:10]])

    assert code == 0 and "Removed 1 entry" in text
    assert store.consume_approval(pending.key) is False


def test_revoke_with_no_match_exits_nonzero(store):
    code, text, _ = _run(store, ["approvals", "revoke", "deadbeefcafe"])
    assert code == 1 and "Nothing matched" in text


def test_unknown_subcommand_prints_usage(store):
    code, text, _ = _run(store, ["approvals", "bogus"])
    assert code == 2 and "usage" in text


def test_help(store):
    code, text, _ = _run(store, ["approvals", "--help"])
    assert code == 0 and "aran approve CODE" in text


# --- dispatch from the real entry point -------------------------------------------

def test_main_dispatches_approval_commands_instead_of_wrapping(tmp_path, monkeypatch, capsys):
    """`aran approvals` must run the approvals CLI, not complain about a
    missing `--` - but `aran -- approvals ...` still wraps a command."""
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")

    code = cli.main(["approvals"], env={})

    assert code == 0
    assert "No pending requests" in capsys.readouterr().out


def test_main_still_requires_the_separator_for_everything_else(capsys):
    code = cli.main(["something-else"], env={})

    assert code == 2
    assert "usage" in capsys.readouterr().err.lower()
