# 12. Human Approval: Approve or Decline a Blocked Call

By default, when the [outbound gate](05-outbound-gate.md) blocks a call, that's the end of it: the agent gets an error and the action doesn't happen. That's safe, but sometimes the block is a false alarm (you really *do* want to run `rm -rf build/`). Human approval turns a plain block into a question for **you**:

> Your agent tried something risky. Here is exactly what, and why it's risky. Allow it, or not?

It is **on by default** and only ever affects outbound blocks (`-32001` signature matches and `-32002` repo-scan matches). It is not a way to loosen the inbound gate, and it never touches the loop guard (`-32003`).

## How it works, step by step

1. Your agent makes a call that matches an output signature.
2. Aran **still blocks it** - nothing runs. But the error now carries an **approval code** like `AR-7K2M9Q`, and Aran tells the agent to relay it to you.
3. At the same time, a **desktop dialog** pops up (where one is available) showing the tool, the exact arguments, a plain-language explanation of the risk, and the code.
4. You decide, in either place:
   - **In the dialog:** *Approve & remember*, *Decline*, or close it to decide later (the macOS dialog also offers *Approve once*; on other platforms use `aran approve CODE --once`).
   - **In your own terminal:** `aran approve AR-7K2M9Q` (add `--once` for a single use) or `aran decline AR-7K2M9Q`.
5. Aran saves your decision, keyed to the **exact call** (tool name plus the exact arguments).
6. The agent retries the identical call. If you approved it, it goes through; if you declined, it stays blocked, and Aran tells the agent you already said no so it doesn't keep asking.

```
agent: run_command {"command": "rm -rf build/"}
aran : BLOCKED - awaiting human approval (code AR-7K2M9Q)      <- agent sees this
you  : (dialog pops up)  Approve & remember
agent: run_command {"command": "rm -rf build/"}   (retry)
aran : forwarded                                                <- logged as allowed, approved_by_user
```

## Why there is no "approve" tool for the agent

This is the most important design decision. Anything your agent can call, a **prompt injection** hidden in a web page or file the agent read can also make it call. If the agent could approve its own blocked call, the gate would protect nothing.

So approval is deliberately **human-only**:

- There is no `aran_approve` tool. (A call to a tool with that name is just forwarded to the wrapped server like any unknown tool; it approves nothing. This is tested.)
- `aran approve` **refuses to run without an interactive terminal** on both stdin and stdout, and asks you to type `y` after showing you the full details. An agent's non-interactive shell tool is rejected.
- Every dialog's **default button is the safe one** (Decline / Decide later), so a stray Enter or Space never approves.
- The agent-visible error message contains only Aran's own words and the code - **never the call's arguments**, which are attacker-controlled in the threat model.

## The commands

```bash
aran approvals                  # pending requests, plus remembered approvals/declines
aran approve AR-7K2M9Q          # review, then type y: remembers the approval
aran approve AR-7K2M9Q --once   # approve a single use only
aran decline AR-7K2M9Q          # decline and remember (no terminal needed)
aran approvals revoke <id>      # forget a remembered approval/decline
```

`aran approvals revoke` takes the key prefix shown by `aran approvals`. After revoking, the same call is blocked (and can be asked about) again.

## What exactly is approved

An approval matches **the exact tool name and the exact arguments**. Approving `rm -rf build/` does not approve `rm -rf /`, or `rm -rf build/ ` with different whitespace. Change anything and Aran asks again. A request left unanswered expires after 15 minutes; the next identical attempt creates a fresh one.

*Approve & remember* persists across sessions until you revoke it. *Approve once* is consumed by the first retry that uses it.

If a single call trips both the signature check and the GitHub repo scan, one approval covers it - you aren't asked twice.

## Where it's stored, and what's logged

- Decisions live as small files under `~/.aran/approvals/`. Each is written atomically, so several IDEs sharing one folder can't corrupt each other.
- Every decision is written to the [audit log](07-audit-log.md) with `direction: "approval"` (outcome `approved` / `declined` / `revoked`, and `via: cli` or `dialog`). A call that went through because of an approval is logged as `allowed` with `detail.approved_by_user: true`, and still records the signature it would have matched. Block entries record `detail.approval_code`.
- `aran_status` shows these as a separate "Human approval decisions" line and does not count them as gated messages.

## Configuration

| Variable | Effect |
| --- | --- |
| `ARAN_APPROVALS=0` (or `false`/`off`/`no`) | Turn the whole feature off: blocks are plain blocks again, exactly as before. |
| `ARAN_APPROVAL_DIALOG=0` | Keep approval but never open a desktop dialog (terminal-only). |

`ARAN_MODE=audit` never creates approval requests, because nothing is blocked in dry-run mode.

On startup Aran prints a one-line stderr notice saying whether a desktop prompt is available.

## Desktop dialog support

| Platform | Mechanism | Needs |
| --- | --- | --- |
| Windows | native message box | nothing |
| macOS | `osascript` dialog | nothing (ships with macOS) |
| Linux | `zenity`, or `kdialog` | one of them, and a display (`DISPLAY` / `WAYLAND_DISPLAY`) |

Without a dialog (headless Linux, SSH sessions) approval is simply terminal-only. Being honest about testing: the Windows dialog has been exercised on a real Windows machine; the macOS and Linux dialogs are covered by unit tests of the exact commands and result parsing, but have not yet been run on real systems. Reports welcome.

## Honest limits

- **The dialog is the strongest channel.** It's a separate window the agent can't type into. The terminal command depends on your agent not having an *interactive* terminal; if your IDE gives agents a real pseudo-terminal, prefer the dialog, or set `ARAN_APPROVALS=0` and rely on plain blocks.
- **An agent with its own shell can bypass Aran entirely.** Aran only gates what flows through the MCP server it wraps. If an agent can run `rm -rf` directly in a built-in terminal tool, no MCP proxy sees it.
- **Protect `~/.aran/`.** If another MCP server gives your agent write access to your home directory, it could in principle drop an approval file there. Don't expose `~/.aran/` to filesystem tools.
- **Exact-match only.** That's a feature, but it means a slightly different command asks again.

## Next

[10. Troubleshooting](10-troubleshooting.md) or back to the [index](README.md).
