# 10. Troubleshooting

Indexed by symptom — find the one you're seeing and jump straight to it.

## `'aran' is not recognized` / `command not found: aran`

**Cause:** the `aran` script isn't on your shell's `PATH`. The package
itself is installed correctly; only the shortcut command isn't reachable.

**Fix:** use `python -m aran.cli` instead everywhere you'd use `aran`
(works regardless of `PATH`), or fix your `PATH` so the short form works
too. Full instructions:
[2. Installation § If `aran` isn't found on your PATH](02-installation.md#if-aran-isnt-found-on-your-path).

## `pip install aran` fails / package not found

**Cause:** Aran isn't published to PyPI yet.

**Fix:** install from source instead:

```bash
git clone https://github.com/aranaisec-cyber/aran.git
cd aran
pip install -e .
```

See [2. Installation](02-installation.md) for the full walkthrough. This
applies to the one-click IDE badges too — they'll configure your IDE
correctly, but the server shows as errored until you've run the above at
least once.

## `usage: aran -- <command to launch the real MCP server> [args...]`

This isn't an error — it's Aran telling you it was run with no command to
wrap. It means the install itself is working correctly. You'll see this
if you run `aran` or `python -m aran.cli` with no arguments; add
`-- <your real server command>` after it. See
[3. Quickstart](03-quickstart.md).

## `[Aran] failed to launch downstream server: ...`

**Cause:** Aran tried to start the command you gave it after `--`, and
that failed — almost always because the command doesn't exist, isn't
executable, or isn't on your `PATH`.

**Fix:** confirm the exact command works on its own, outside Aran, first.
For example, if you're wrapping `npx -y @modelcontextprotocol/server-filesystem /path`,
run just `npx -y @modelcontextprotocol/server-filesystem /path` by itself
and confirm it starts before adding Aran in front of it. A typo in the
server name or a missing runtime (Node.js for `npx`-based servers, `uv`
for `uvx`-based ones) is the usual cause.

## `[Aran] warning: could not load <path> (...), using N built-in ... signatures instead` {#rules-file-warning}

**Cause:** the rules file
([`src/aran/default-rules.yaml`](../../src/aran/default-rules.yaml)) is
missing, unreadable, not valid YAML, or has a malformed
`input_gate_signatures`/`output_gate_signatures` value. Aran doesn't crash
or fail closed over a bad config file — it falls back to a small built-in
default list (4 input phrases, 3 output patterns) instead, and warns you
so the fallback isn't silent.

**Fix:** this usually means either a broken editable install (reinstall
with `pip install -e .` from the repo root) or a rules file you edited by
hand that's no longer valid YAML — check indentation and that both keys
are lists of plain strings. Confirm the fix by re-running any command and
checking the warning is gone.

## A message that should have been blocked/redacted wasn't (false negative)

**Cause:** almost certainly a phrasing not covered by any current
signature — both gates are pattern-based (see
[5. The Outbound Gate](05-outbound-gate.md) and
[6. The Inbound Gate](06-inbound-gate.md)), so a genuinely novel attack
can slip through if it doesn't match anything in the rules file.

**Fix:** [open an issue](https://github.com/aranaisec-cyber/aran/issues)
with the exact content that should have been caught, so a new signature
can be added. In the meantime, you can add your own pattern directly to
`src/aran/default-rules.yaml`.

## Something legitimate got blocked/redacted (false positive)

**Cause:** the shipped signature set is generated from a public labeled
dataset and, like any pattern-based detector, can occasionally flag
benign content.

**Fix:**

1. Find the exact `matched_signature` in `~/.aran/audit.jsonl` (see
   [7. The Audit Log](07-audit-log.md)).
2. [Open an issue](https://github.com/aranaisec-cyber/aran/issues/new?template=false_positive.yml)
   with that signature and the offending text.
3. In the meantime, remove or adjust that entry in
   `src/aran/default-rules.yaml` for your own local copy — no code changes
   needed, it's a plain YAML list.

Full detail: [8. Modes & Configuration § Reporting a false positive](08-modes-and-configuration.md#reporting-a-false-positive).

## Your IDE shows the server as "errored" or "disconnected" after wrapping it

**Checklist:**

1. Confirm the *original* command (without Aran in front of it) still
   works when run directly in a terminal — if the underlying server is
   broken, wrapping it with Aran won't fix that.
2. Confirm your config's `command` field is actually `aran` (or `python`
   with `-m`, `aran.cli`, `--` as the first args) and not still the
   original server binary — a copy-paste that missed the `command` field
   is the most common mistake. See
   [4. Wiring Aran into Your IDE](04-ide-integration.md).
3. Confirm Aran itself is installed and resolvable — run
   `python -m aran.cli` (no other arguments) in a terminal and confirm you
   see the usage message from [2. Installation](02-installation.md), not
   a "module not found" error.

## The proxy exits with code `3` and the child process exited `0`

**Cause:** this specific exit code means the *relay itself* degraded (a
message it received couldn't be safely inspected, or one of its internal
threads died) even though the server process you wrapped exited cleanly.
This is intentional — without a distinct code here, a malformed or
hostile server response could silently disable the gate while your IDE
sees a normal, healthy exit.

**Fix:** this points at a message shape Aran couldn't handle. Please
[open an issue](https://github.com/aranaisec-cyber/aran/issues) — include
which server you were wrapping and, if you can reproduce it, the specific
call that triggered it (redact anything sensitive first).

## Still stuck?

- Re-run the exact examples in [9. Hands-On Walkthrough](09-hands-on-walkthrough.md)
  against the practice server (`tests/fixtures/fake_server.py`) to
  isolate whether the problem is in Aran itself or specific to the real
  server you're wrapping.
- Check [SECURITY.md](../../SECURITY.md) if the issue is a genuine
  security concern rather than a usage question — that has a separate,
  responsible-disclosure reporting path.
- Otherwise, [open an issue](https://github.com/aranaisec-cyber/aran/issues)
  with the exact command you ran and the exact output you got.

## Next

[11. FAQ](11-faq.md) for quick answers that don't need a full
troubleshooting entry.
