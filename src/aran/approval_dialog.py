"""A native desktop prompt for approving a blocked call - the human-only
channel that works the same in every IDE, because Aran opens it itself
rather than asking the IDE or the agent to.

The dialog returns one of "approve" (remember), "once", "decline", or None
("decide later" - closing it or hitting Escape records nothing, so the
pending entry stays available to `aran approve`). Every dialog's default
button is the safe one, so an accidental Enter never approves.

Platform support: Windows (MessageBox via ctypes) and macOS (osascript) need
nothing installed; Linux needs zenity or kdialog and a display. Where none is
available, default_dialog() returns None and approval is terminal-only.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import threading
from typing import Callable

from aran.approvals import ApprovalError, ApprovalStore, PendingApproval, format_review

DialogFn = Callable[[PendingApproval], "str | None"]

_TITLE = "Aran - approval needed"
# Matches the pending entry's lifetime: a dialog nobody answers by then is
# moot anyway, and the subprocess must not outlive its usefulness.
_DIALOG_TIMEOUT_SECONDS = 900


def dialog_text(pending: PendingApproval) -> str:
    return (
        "Aran blocked a risky tool call from your AI agent.\n\n"
        f"{format_review(pending)}\n\n"
        "Approve this exact call?"
    )


# -- Windows ---------------------------------------------------------------

_MB_YESNOCANCEL = 0x3
_MB_ICONWARNING = 0x30
_MB_DEFBUTTON2 = 0x100  # "No" - Enter/Space on this dialog must never approve
_MB_SETFOREGROUND = 0x10000
_MB_TOPMOST = 0x40000
_IDYES, _IDNO = 6, 7


def _windows_decision(button_id: int) -> str | None:
    return {_IDYES: "approve", _IDNO: "decline"}.get(button_id)


def _windows_dialog(pending: PendingApproval) -> str | None:
    import ctypes

    text = (
        dialog_text(pending)
        + "\n\nYes = approve and remember     No = decline     Cancel = decide later"
    )
    flags = _MB_YESNOCANCEL | _MB_ICONWARNING | _MB_DEFBUTTON2 | _MB_SETFOREGROUND | _MB_TOPMOST
    button = ctypes.windll.user32.MessageBoxW(0, text, _TITLE, flags)
    return _windows_decision(button)


# -- macOS -----------------------------------------------------------------

_MAC_BUTTONS = {"Decline": "decline", "Approve once": "once", "Approve & remember": "approve"}


def _applescript_quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _mac_command(pending: PendingApproval) -> list[str]:
    script = (
        f"display dialog {_applescript_quote(dialog_text(pending))} "
        f"with title {_applescript_quote(_TITLE)} "
        'buttons {"Decline", "Approve once", "Approve & remember"} '
        'default button "Decline" with icon caution'
    )
    return ["osascript", "-e", script]


def _mac_parse(returncode: int, stdout: str) -> str | None:
    if returncode != 0:  # Escape / cancel => osascript error -128
        return None
    for label, decision in _MAC_BUTTONS.items():
        if f"button returned:{label}" in stdout:
            return decision
    return None


def _mac_dialog(pending: PendingApproval) -> str | None:
    result = subprocess.run(_mac_command(pending), capture_output=True, text=True, timeout=_DIALOG_TIMEOUT_SECONDS)
    return _mac_parse(result.returncode, result.stdout)


# -- Linux -----------------------------------------------------------------

def _zenity_command(pending: PendingApproval) -> list[str]:
    return [
        "zenity", "--question", "--title", _TITLE, "--no-markup",
        "--text", dialog_text(pending),
        "--ok-label", "Approve & remember",
        "--cancel-label", "Decide later",
        "--extra-button", "Decline",
        "--default-cancel",
    ]


def _zenity_parse(returncode: int, stdout: str) -> str | None:
    if "Decline" in stdout:
        return "decline"
    return "approve" if returncode == 0 else None


def _kdialog_command(pending: PendingApproval) -> list[str]:
    return ["kdialog", "--title", _TITLE, "--yesnocancel", dialog_text(pending),
            "--yes-label", "Approve & remember", "--no-label", "Decline", "--cancel-label", "Decide later"]


def _kdialog_parse(returncode: int, stdout: str) -> str | None:
    return {0: "approve", 1: "decline"}.get(returncode)


def _linux_dialog(builder: Callable[[PendingApproval], list[str]], parse: Callable[[int, str], "str | None"]) -> DialogFn:
    def dialog(pending: PendingApproval) -> str | None:
        result = subprocess.run(builder(pending), capture_output=True, text=True, timeout=_DIALOG_TIMEOUT_SECONDS)
        return parse(result.returncode, result.stdout)

    return dialog


_FALSY = ("0", "false", "off", "no")


def default_dialog(
    env: dict[str, str],
    *,
    platform: str = sys.platform,
    which: Callable[[str], "str | None"] = shutil.which,
) -> DialogFn | None:
    """The native dialog for this machine, or None when there isn't one
    (headless Linux, no zenity/kdialog) or ARAN_APPROVAL_DIALOG turns it off.
    None is never an error - approval still works through `aran approve`."""
    if env.get("ARAN_APPROVAL_DIALOG", "").strip().lower() in _FALSY:
        return None
    if platform == "win32":
        return _windows_dialog
    if platform == "darwin":
        return _mac_dialog if which("osascript") else None
    if platform.startswith("linux"):
        if not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")):
            return None
        if which("zenity"):
            return _linux_dialog(_zenity_command, _zenity_parse)
        if which("kdialog"):
            return _linux_dialog(_kdialog_command, _kdialog_parse)
    return None


def make_notifier(
    store: ApprovalStore,
    dialog: DialogFn,
    *,
    on_error: Callable[[str], None] | None = None,
) -> Callable[[PendingApproval], threading.Thread]:
    """Returns the callback the gate calls when a NEW pending approval is
    created. The dialog blocks until a human answers, so it runs on a daemon
    thread - the relay never waits on a person. If the proxy exits first the
    thread dies with it and the pending entry simply remains for the
    terminal command."""

    def run(pending: PendingApproval) -> None:
        try:
            decision = dialog(pending)
            if decision == "approve":
                store.approve(pending.code, via="dialog")
            elif decision == "once":
                store.approve(pending.code, once=True, via="dialog")
            elif decision == "decline":
                store.decline(pending.code, via="dialog")
        except ApprovalError:
            pass  # already decided through the terminal while the dialog was open
        except Exception as e:  # noqa: BLE001 - a dialog failure must never reach the relay
            if on_error:
                on_error(f"[Aran] approval dialog failed: {e!r}")

    def notify(pending: PendingApproval) -> threading.Thread:
        thread = threading.Thread(target=run, args=(pending,), daemon=True, name="aran-approval-dialog")
        thread.start()
        return thread  # the gate ignores it; tests join it

    return notify
