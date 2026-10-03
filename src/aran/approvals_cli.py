"""`aran approvals` / `aran approve CODE` / `aran decline CODE`.

The terminal half of human approval (the desktop dialog is the other - see
approval_dialog.py). Approving is deliberately the one command here that is
not scriptable: it needs an interactive terminal on both stdin and stdout and
asks a typed yes/no after showing the risk, because an agent driving a
non-interactive shell tool is exactly who this must not be usable by. Declining
and revoking only ever *reduce* what's allowed, so they have no such gate.
"""
from __future__ import annotations

import sys
from typing import Callable, TextIO

from aran.approvals import ApprovalError, ApprovalStore, format_review

APPROVAL_COMMANDS = ("approve", "decline", "approvals")

HELP = """\
usage:
  aran approvals                 list pending requests and remembered decisions
  aran approve CODE [--once]     review a blocked call and approve it (interactive terminal only)
  aran decline CODE              decline it (and remember not to ask again)
  aran approvals revoke ID       forget a remembered approval/decline (ID from `aran approvals`)
"""


def _interactive() -> bool:
    return bool(sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty())


def _ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


def _list(store: ApprovalStore, out: TextIO) -> int:
    now = store.clock()
    pending = store.list_pending()
    approved, declined = store.list_decisions()
    if not (pending or approved or declined):
        print("No pending requests and no remembered decisions.", file=out)
        return 0
    if pending:
        print("Pending (waiting for a human):", file=out)
        for p in pending:
            print(
                f"  {p.code}  {p.tool_name}  - {p.risk}  (expires in {_ago(p.expires_at - now)})",
                file=out,
            )
        print("  -> review and approve with:  aran approve CODE", file=out)
    if approved:
        print("Remembered approvals:", file=out)
        for a in approved:
            kind = "once" if a.get("once") else "remembered"
            print(f"  {a['key'][:10]}  {a.get('tool_name')}  ({kind}, via {a.get('via')})", file=out)
    if declined:
        print("Remembered declines:", file=out)
        for d in declined:
            print(f"  {d['key'][:10]}  {d.get('tool_name')}  (via {d.get('via')})", file=out)
    return 0


def run(
    argv: list[str],
    *,
    store: ApprovalStore,
    out: TextIO | None = None,
    input_fn: Callable[[str], str] = input,
    is_interactive: Callable[[], bool] = _interactive,
) -> int:
    out = out or sys.stdout
    command, rest = argv[0], argv[1:]

    if command == "approvals":
        sub = rest[0] if rest else "list"
        if sub == "list":
            return _list(store, out)
        if sub == "revoke" and len(rest) == 2:
            try:
                removed = store.revoke(rest[1])
            except ApprovalError as e:
                print(f"aran: {e}", file=out)
                return 1
            print(f"Removed {removed} entr{'y' if removed == 1 else 'ies'}." if removed else "Nothing matched.", file=out)
            return 0 if removed else 1
        print(HELP, file=out, end="")
        return 0 if sub in ("help", "-h", "--help") else 2

    once = "--once" in rest
    positional = [a for a in rest if not a.startswith("--")]
    if len(positional) != 1:
        print(HELP, file=out, end="")
        return 2
    code = positional[0]

    try:
        if command == "decline":
            pending = store.decline(code, via="cli")
            print(f"Declined {pending.code}. Aran will not ask about this exact call again.", file=out)
            return 0

        # approve
        if not is_interactive():
            print(
                "aran: approving needs an interactive terminal (stdin and stdout must be a TTY).\n"
                "This is deliberate: approval is a human decision, so it can't be scripted or\n"
                "run by an agent's non-interactive shell. Open a real terminal and run it there.",
                file=out,
            )
            return 1
        pending = store.get_pending(code)
        if pending is None:
            raise ApprovalError(f"no pending approval {code.strip().upper()!r} (unknown, already decided, or expired)")
        print(format_review(pending), file=out)
        print(file=out)
        answer = input_fn(f"Approve this exact call{' (one time only)' if once else ' and remember it'}? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print(f"Not approved - no decision recorded. (`aran decline {pending.code}` to decline it.)", file=out)
            return 1
        store.approve(pending.code, once=once, via="cli")
        print(
            f"Approved {pending.code}{' (one time)' if once else ''}. "
            "The agent can now retry the call.",
            file=out,
        )
        return 0
    except ApprovalError as e:
        print(f"aran: {e}", file=out)
        return 1
    except OSError as e:
        print(f"aran: could not read or write the approvals store: {e}", file=out)
        return 1
