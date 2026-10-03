from pathlib import Path

import pytest

from aran import approval_dialog as dlg
from aran.approvals import KIND_SIGNATURE, ApprovalStore, call_key


@pytest.fixture
def store(tmp_path: Path) -> ApprovalStore:
    return ApprovalStore(tmp_path / "approvals")


def _pending(store: ApprovalStore):
    args = {"command": 'rm -rf "/tmp/my dir"\nsecond line'}
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


# --- which dialog a machine gets ---------------------------------------------

def test_windows_always_has_a_dialog():
    assert dlg.default_dialog({}, platform="win32") is dlg._windows_dialog


def test_macos_needs_osascript():
    assert dlg.default_dialog({}, platform="darwin", which=lambda n: "/usr/bin/osascript") is dlg._mac_dialog
    assert dlg.default_dialog({}, platform="darwin", which=lambda n: None) is None


def test_linux_needs_a_display():
    assert dlg.default_dialog({}, platform="linux", which=lambda n: "/usr/bin/zenity") is None
    assert dlg.default_dialog({"DISPLAY": ":0"}, platform="linux", which=lambda n: "/usr/bin/zenity") is not None
    assert dlg.default_dialog({"WAYLAND_DISPLAY": "w0"}, platform="linux", which=lambda n: "/usr/bin/zenity") is not None


def test_linux_without_zenity_or_kdialog_has_no_dialog():
    assert dlg.default_dialog({"DISPLAY": ":0"}, platform="linux", which=lambda n: None) is None


def test_linux_falls_back_to_kdialog():
    chosen = dlg.default_dialog(
        {"DISPLAY": ":0"}, platform="linux", which=lambda n: "/usr/bin/kdialog" if n == "kdialog" else None
    )
    assert chosen is not None


@pytest.mark.parametrize("value", ["0", "false", "off", "no", "OFF"])
def test_the_dialog_can_be_switched_off(value):
    assert dlg.default_dialog({"ARAN_APPROVAL_DIALOG": value}, platform="win32") is None


def test_unknown_platform_has_no_dialog():
    assert dlg.default_dialog({}, platform="freebsd13") is None


# --- Windows -------------------------------------------------------------------

def test_windows_button_mapping_never_treats_cancel_as_a_decision():
    assert dlg._windows_decision(6) == "approve"
    assert dlg._windows_decision(7) == "decline"
    assert dlg._windows_decision(2) is None  # Cancel / Escape -> decide later


def test_windows_default_button_is_the_safe_one():
    # MB_DEFBUTTON2 on a Yes/No/Cancel box is "No": a stray Enter must not approve.
    assert dlg._MB_DEFBUTTON2 == 0x100
    assert dlg._MB_YESNOCANCEL == 0x3


# --- macOS ----------------------------------------------------------------------

def test_mac_command_has_three_buttons_and_declines_by_default(store):
    command = dlg._mac_command(_pending(store))

    assert command[:2] == ["osascript", "-e"]
    assert 'default button "Decline"' in command[2]
    assert '"Approve once"' in command[2] and '"Approve & remember"' in command[2]


def test_mac_script_escapes_quotes_backslashes_and_newlines(store):
    script = dlg._mac_command(_pending(store))[2]

    assert '\\"command\\"' in script  # the dialog text's own quotes are escaped
    assert '\\\\\\"/tmp/my dir\\\\\\"' in script  # JSON's \" becomes \\\" inside AppleScript
    assert "\\n" in script
    assert "\n" not in script  # no raw newline inside the AppleScript source


@pytest.mark.parametrize("stdout,expected", [
    ("button returned:Decline, gave up:false", "decline"),
    ("button returned:Approve once, gave up:false", "once"),
    ("button returned:Approve & remember, gave up:false", "approve"),
    ("", None),
])
def test_mac_parse(stdout, expected):
    assert dlg._mac_parse(0, stdout) == expected


def test_mac_cancel_is_decide_later():
    assert dlg._mac_parse(1, "") is None


# --- Linux -----------------------------------------------------------------------

def test_zenity_parse():
    assert dlg._zenity_parse(0, "") == "approve"
    assert dlg._zenity_parse(1, "Decline\n") == "decline"
    assert dlg._zenity_parse(1, "") is None  # "Decide later" / closed


def test_zenity_defaults_to_the_cancel_button(store):
    assert "--default-cancel" in dlg._zenity_command(_pending(store))


def test_kdialog_parse():
    assert dlg._kdialog_parse(0, "") == "approve"
    assert dlg._kdialog_parse(1, "") == "decline"
    assert dlg._kdialog_parse(2, "") is None


# --- the text a human reads -------------------------------------------------------

def test_dialog_text_shows_what_would_run_and_why_it_is_risky(store):
    text = dlg.dialog_text(_pending(store))

    assert "rm -rf" in text
    assert "Deletes things." in text
    assert "Approve this exact call?" in text


# --- the notifier -------------------------------------------------------------------

def _run_notifier(store, decision, **kwargs):
    def fake_dialog(pending):
        if isinstance(decision, Exception):
            raise decision
        return decision

    pending = _pending(store)
    thread = dlg.make_notifier(store, fake_dialog, **kwargs)(pending)
    thread.join(5)
    assert not thread.is_alive()
    return pending


def test_notifier_approve_remembers(store):
    pending = _run_notifier(store, "approve")
    assert store.consume_approval(pending.key) is True


def test_notifier_once_is_single_use(store):
    pending = _run_notifier(store, "once")
    assert store.consume_approval(pending.key) is True
    assert store.consume_approval(pending.key) is False


def test_notifier_decline_is_remembered(store):
    pending = _run_notifier(store, "decline")
    assert store.status(pending.key) == "declined"


def test_notifier_decide_later_leaves_the_request_pending(store):
    pending = _run_notifier(store, None)

    assert store.status(pending.key) is None
    assert store.get_pending(pending.code) is not None


def test_a_crashing_dialog_is_reported_not_raised(store):
    errors = []
    pending = _run_notifier(store, RuntimeError("no display"), on_error=errors.append)

    assert store.get_pending(pending.code) is not None
    assert errors and "no display" in errors[0]


def test_a_decision_already_made_in_the_terminal_is_not_an_error(store):
    pending = _pending(store)

    def dialog(p):
        store.decline(p.code, via="cli")  # the human answered in the terminal first
        return "approve"

    errors = []
    dlg.make_notifier(store, dialog, on_error=errors.append)(pending).join(5)

    assert errors == []
    assert store.status(pending.key) == "declined"  # the terminal decision stands
