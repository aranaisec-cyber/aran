# 8. Modes & Configuration

Aran needs zero configuration to protect you — install it, wrap your
server, done. This page covers the optional knobs: a dry-run mode for
tuning before you enforce, a profiler for performance visibility, and how
to change or refresh the signature rules themselves.

## `ARAN_MODE=audit` — dry-run mode

Set this environment variable and Aran evaluates every gate exactly as
normal, but **never actually blocks or redacts anything** — a match is
logged as `would_block` instead of `blocked`, and the original
call/content is forwarded completely unmodified.

```bash
ARAN_MODE=audit aran -- npx -y @modelcontextprotocol/server-filesystem /path
```

When this is active, Aran prints a notice to stderr on every single
startup — deliberately, so you never forget it's on:

```
[Aran] audit mode (ARAN_MODE=audit): blocking and redaction are disabled, matches are logged only
```

**Why use it:** the shipped signature set is generated from a public
labeled dataset and, like any pattern-based detector, can occasionally
flag something benign. Before you rely on Aran in enforcing mode against
a new server or an unusual workload, run it in audit mode for a while,
then check `~/.aran/audit.jsonl` for `would_block` entries — that's a
list of everything that *would* have been blocked, without you having
actually lost any functionality while you check whether each one is a
real threat or a false positive.

**Worked example** — the exact same destructive call from
[5. The Outbound Gate](05-outbound-gate.md), run under audit mode instead:

```bash
printf '%s\n' '{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}}}' \
  | ARAN_MODE=audit python -m aran.cli -- python tests/fixtures/fake_server.py
```

```json
{"jsonrpc": "2.0", "id": 4, "result": {"content": [{"type": "text", "text": "ran run_command"}]}}
```

Compare against the enforcing-mode result in
[5. The Outbound Gate](05-outbound-gate.md) — same input, but this time
the call actually reached the practice server and its real reply came
back. The audit log still records what happened, just with a different
outcome:

```json
{"timestamp": "...", "direction": "outbound", "tool_name": "run_command", "outcome": "would_block", "matched_signature": "rm\\s+-[rfRF]+"}
```

**Important:** this is a global switch for the whole proxy session — it
affects both gates identically. There's no way to audit-mode one gate
while enforcing the other. It's meant as a temporary tuning tool, not a
permanent operating mode — leaving it on gives you visibility with no
actual protection.

## `ARAN_PROFILE=1` — timing visibility

Set this (or `true`/`yes`/`on` — any value other than empty, `0`, or
`false`) and Aran prints one timing line to stderr per gated message:

```bash
ARAN_PROFILE=1 aran -- npx -y @modelcontextprotocol/server-filesystem /path
```

Example output:

```
[Aran Profiler] Checked outbound call against 10 signatures in 1.71ms
[Aran Profiler] Audited 5 JSON leaf nodes against 207 signatures in 1.27ms
```

The first line is from the outbound gate (how long the signature check
against the call's arguments took); the second is from the inbound gate
(how many individual string values the scan visited in the response, and
how long that took). Use this if you're wrapping a server with very
large responses and want to confirm Aran isn't adding noticeable latency
— in practice, both checks are typically low-single-digit milliseconds
even against real signature-set sizes.

Both `ARAN_MODE` and `ARAN_PROFILE` are independent and combine freely:

```bash
ARAN_MODE=audit ARAN_PROFILE=1 aran -- <your command>
```

Both are read **once, at startup, from the environment Aran itself was
launched with** — the downstream server you're wrapping has no way to set
or influence either one.

## The rules file

The actual signatures both gates check against live in a YAML file
shipped inside the installed package:
[`src/aran/default-rules.yaml`](../../src/aran/default-rules.yaml). It has
two top-level keys:

```yaml
input_gate_signatures:
  - "ignore previous instructions"
  - "system override"
  # ... hundreds more, one prompt-injection phrasing per line

output_gate_signatures:
  - "rm\\s+-[rfRF]+"
  - "chmod\\s+777"
  # ... destructive command patterns
```

- `input_gate_signatures` feeds [the inbound gate](06-inbound-gate.md).
- `output_gate_signatures` feeds [the outbound gate](05-outbound-gate.md).

If this file is ever missing, unreadable, not valid YAML, or has a
malformed value for either key, Aran does **not** crash and does **not**
fail open — it falls back to a small built-in default list (the four
input phrases and three output patterns shown earlier in this guide) and
prints a one-time warning to stderr telling you exactly which key fell
back and why. See
[10. Troubleshooting](10-troubleshooting.md#rules-file-warning) if you see
this warning.

### Refreshing the signature set

The shipped rules are generated from a live, labeled public dataset. To
pull the latest version:

```bash
python scripts/sync_threat_intel.py
```

This overwrites `src/aran/default-rules.yaml` with a fresh signature list.
Review the diff before committing if you're maintaining a fork with local
customizations.

### Reporting a false positive

If something you know to be benign gets blocked or redacted:

1. Find the entry in `~/.aran/audit.jsonl` and note its
   `matched_signature` (see [7. The Audit Log](07-audit-log.md)).
2. [Open an issue](https://github.com/aranaisec-cyber/aran/issues/new?template=false_positive.yml)
   with that signature and the offending text.

You can also edit `src/aran/default-rules.yaml` directly to remove or
adjust a signature for your own local copy while you wait — it's a plain
list, no code changes needed.

## Next

[9. Hands-On Walkthrough](09-hands-on-walkthrough.md) — put everything
from this guide together in one extended, copy-pasteable session covering
every case in both gates.
