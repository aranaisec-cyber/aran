# 7. The Audit Log

Every message either gate evaluates gets exactly one line appended to a
local file: `~/.aran/audit.jsonl` (your home directory — `~` on
Linux/macOS, `C:\Users\<you>` on Windows). This page explains the format
and how to actually use it, not just read it.

## Format

The file is [JSON Lines](https://jsonlines.org/) — one complete, valid
JSON object per line, newest at the bottom. Read the newest entries with:

```bash
tail -n 10 ~/.aran/audit.jsonl
```

Or watch it live while you work:

```bash
tail -f ~/.aran/audit.jsonl
```

## Fields

Every line has exactly five fields (see
[`src/aran/audit.py`](../../src/aran/audit.py) for the code that writes
them):

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | string | UTC timestamp, ISO 8601, of when this message was gated. |
| `direction` | `"outbound"` or `"inbound"` | `outbound` = a tool call going to the server (checked by [the outbound gate](05-outbound-gate.md)). `inbound` = a response coming back from the server (checked by [the inbound gate](06-inbound-gate.md)). |
| `tool_name` | string or `null` | Which tool the call/result belongs to. `null` for inbound messages that aren't a response to a `tools/call` (e.g. an `initialize` response). |
| `outcome` | one of `allowed`, `blocked`, `would_block`, `error` | See below. |
| `matched_signature` | string or `null` | The exact regex/phrase that matched, or `null` if nothing did. |

## The four outcomes

- **`allowed`** — nothing matched. The message passed through completely
  unmodified. This is the expected outcome for the overwhelming majority
  of your traffic.
- **`blocked`** — a signature matched, in normal (enforcing) mode. For an
  outbound call, this means the call never reached the real server. For
  an inbound message, this means the matching string was replaced with
  the redaction notice.
- **`would_block`** — a signature matched, but Aran is running in
  **dry-run mode** (`ARAN_MODE=audit`), so the call/content was forwarded
  unmodified anyway. This outcome exists specifically so you can see what
  *would* have been blocked before actually turning enforcement on — see
  [8. Modes & Configuration](08-modes-and-configuration.md).
- **`error`** — Aran itself hit a problem processing the message. This is
  distinct from a signature match; see
  [10. Troubleshooting](10-troubleshooting.md) if you see this outcome
  regularly.

## Worked example: reading a real session

After running the destructive-command and injection examples from
[3. Quickstart](03-quickstart.md), your audit log's newest lines look
like this:

```json
{"timestamp": "2026-09-29T23:41:45.907404+00:00", "direction": "outbound", "tool_name": "list_files", "outcome": "allowed", "matched_signature": null}
{"timestamp": "2026-09-29T23:41:45.950234+00:00", "direction": "inbound", "tool_name": "list_files", "outcome": "allowed", "matched_signature": null}
{"timestamp": "2026-09-29T23:41:56.351569+00:00", "direction": "outbound", "tool_name": "run_command", "outcome": "blocked", "matched_signature": "rm\\s+-[rfRF]+"}
{"timestamp": "2026-09-29T23:42:09.106954+00:00", "direction": "outbound", "tool_name": "echo_injection", "outcome": "allowed", "matched_signature": null}
{"timestamp": "2026-09-29T23:42:09.147561+00:00", "direction": "inbound", "tool_name": "echo_injection", "outcome": "blocked", "matched_signature": "ignore\\ previous\\ instructions"}
```

Reading this narratively: a clean `list_files` call went out and came
back clean; a `run_command` call was blocked outbound before it ever
reached the server (no matching inbound line for it, because it never
got a response); and an `echo_injection` call itself was clean going out,
but its *response* got caught by the inbound gate and redacted.

Notice the two gates are logged independently, keyed by direction — a
single tool call can appear in your log as `allowed` outbound and
`blocked` inbound (a clean request that got a poisoned response), or vice
versa (a dangerous request that never even got a chance to respond).

## What to actually do with this file

- **Prove protection is active.** If you've wired Aran into your IDE and
  want to confirm it's really in the path (not just that the server shows
  as "connected"), do something with your agent and check for a fresh
  line here — see
  [4. Wiring Aran into Your IDE](04-ide-integration.md#confirming-aran-is-actually-running).
- **Investigate a false positive.** If legitimate content got redacted or
  a legitimate call got blocked, find the corresponding line and its
  `matched_signature` — that tells you exactly which rule fired, so you
  can decide whether to adjust your rules file (see
  [8. Modes & Configuration](08-modes-and-configuration.md)) or report it
  upstream.
- **Tune before enforcing.** Run in `ARAN_MODE=audit` first (see next
  page), watch for `would_block` entries over real usage, and only switch
  to enforcing once you're confident the signature set fits your traffic.
- **Post-incident review.** Because every gated message is logged
  locally with a timestamp, you have a durable record of exactly what was
  blocked or redacted and when, independent of your IDE's own history.

## What this file is *not*

It is **not** a full request/response capture — it does not store the
actual message content (beyond the one matched signature string), and it
never leaves your machine. It's a decision log, not a wiretap. If you need
to see the exact content that triggered a match, reproduce it by hand
using the pattern in [3. Quickstart](03-quickstart.md) or
[9. Hands-On Walkthrough](09-hands-on-walkthrough.md).

## Next

[8. Modes & Configuration](08-modes-and-configuration.md) — dry-run mode,
the profiler, and how to edit the rules Aran gates against.
