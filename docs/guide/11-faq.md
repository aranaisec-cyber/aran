# 11. FAQ

**Does Aran modify the MCP server I'm wrapping?**
No. Aran launches the real server as an unmodified subprocess and relays
messages to and from it. The server has no idea Aran is there.

**How do I check Aran is actually working without digging through log
files?**
Ask your agent *"what's aran's status?"* — Aran answers a built-in
`aran_status` tool directly, in your normal chat, with a plain-text
summary of what it's gated recently. See
[4. Wiring Aran into Your IDE § Confirming Aran is actually running](04-ide-integration.md#confirming-aran-is-actually-running).

**Does my agent understand Aran's error codes and redaction notices on
its own, or does it need to be taught?**
On its own, automatically. Aran appends a short explanation to every
session's `initialize` response — the MCP mechanism a client is supposed
to feed to the model at connection time — so the agent already knows what
a `-32001`/`-32002` block or a `[Aran] content blocked: ...` result means
the first time it sees one, without an extra round trip to figure it out
or ask you. See
[4. Wiring Aran into Your IDE § Your agent already knows about Aran](04-ide-integration.md#your-agent-already-knows-about-aran-before-you-ask-anything).

**Does Aran send any data anywhere?**
No, by default. Aran's telemetry — the audit log and the
`aran_status`/`aran_explain` tools — is local IDE telemetry in the literal
sense: generated on your machine, read on your machine, never
transmitted. The only output beyond relaying your existing MCP traffic is
a local audit log file (`~/.aran/audit.jsonl`) on your own machine.
Nothing is sent over the network, and there's no remote analytics,
account, or cloud component. See [7. The Audit Log](07-audit-log.md).

The one opt-in exception is `ARAN_SCAN_GITHUB_REPOS=1` (off by default,
see [8. Modes & Configuration](08-modes-and-configuration.md#optional-aran_scan_github_repos1--scan-a-repo-before-its-cloned)):
when enabled, Aran downloads (never uploads) a public GitHub repo's
contents to scan them before a call that would clone it is allowed
through. That's a read from GitHub, not data leaving your machine — but
it is a real network request, and it's the only feature in Aran that
makes one, which is why it's opt-in rather than the default.

**Does Aran slow down my agent?**
Both checks are regex pattern matching against a signature list, done
in-process — measured in low single-digit milliseconds per message even
against the full shipped rule set (hundreds of signatures). Use
`ARAN_PROFILE=1` to see exact timings for your own workload:
[8. Modes & Configuration](08-modes-and-configuration.md).

**Can I use Aran with a server that isn't MCP-over-stdio (e.g. HTTP/SSE)?**
Not currently — Aran wraps a stdio subprocess specifically. This is the
transport used by the majority of local MCP servers (filesystem, fetch,
shell, database connectors run locally), which is the scope this project
targets today.

**What happens if Aran itself crashes or the server it's wrapping
crashes?**
Aran relays the child process's actual exit code, with one deliberate
exception: if the relay itself degraded (couldn't safely inspect a
message) while the child exited cleanly, Aran exits with code `3` instead
of `0`, specifically so that failure isn't silently invisible to your
IDE. See [10. Troubleshooting](10-troubleshooting.md#the-proxy-exits-with-code-3-and-the-child-process-exited-0).

**Is Aran a replacement for reviewing what tools I give my agent access
to?**
No. Aran catches known-destructive commands and known prompt-injection
phrasings — a real and meaningful layer of defense, but not a substitute
for deciding carefully what an agent is allowed to touch in the first
place. See [1. What Is Aran?](01-what-is-aran.md#what-aran-deliberately-does-not-do).

**Can a false positive break my workflow?**
It can, in the sense that a legitimate call or piece of content could in
principle match a signature it shouldn't. Three mitigations: run
`ARAN_MODE=audit` to see what *would* be blocked before enforcing; ask
`aran_explain` to check a specific command before running it; and once
you find a real false positive, add its exact `matched_signature` to
`~/.aran/allowlist.yaml` — a personal, durable override that survives a
rules-file refresh (unlike editing `default-rules.yaml` directly). See
[8. Modes & Configuration](08-modes-and-configuration.md) and
[10. Troubleshooting](10-troubleshooting.md#something-legitimate-got-blockedredacted-false-positive).

**My agent seems stuck calling the same tool over and over — can Aran
catch that?**
Optionally: `ARAN_LOOP_GUARD=1` blocks a call once it repeats identically
past a threshold within a time window — a frequency check, not a content
one, so it catches a stuck loop even when every individual call looks
completely harmless. Off by default, because a fast *intentional* repeat
(polling, a deliberate retry) looks the same as a stuck loop by design.
See [8. Modes & Configuration](08-modes-and-configuration.md#optional-aran_loop_guard1--block-a-runawaylooping-agent).

**How is this different from a firewall or antivirus?**
Both of those operate at a layer that can't see this specific
conversation — a firewall sees network packets, not the JSON-RPC messages
flowing over an MCP server's stdio; antivirus scans files, not a live
tool-call/tool-result exchange. Aran sits directly inline in that
exchange. See [1. What Is Aran?](01-what-is-aran.md#the-problem).

**Where do the destructive-command and prompt-injection signatures come
from, and can I see them?**
Yes — they're a plain YAML file that ships with the package:
[`src/aran/default-rules.yaml`](../../src/aran/default-rules.yaml). The
prompt-injection list is generated from a public labeled dataset via
`python scripts/sync_threat_intel.py`. Nothing about the detection logic
is hidden or proprietary. See
[8. Modes & Configuration](08-modes-and-configuration.md).

**I found a real security vulnerability in Aran itself — where do I
report it?**
Not as a normal GitHub issue — see [SECURITY.md](../../SECURITY.md) for
the responsible-disclosure process and scope.

**Is Aran production-ready?**
It's early (pre-1.0) but the core proxy — bidirectional gating, YAML
config, the audit log — is implemented and tested, including against an
adversarial hostile-server test suite (see
[9. Hands-On Walkthrough § Steps 10–11](09-hands-on-walkthrough.md#step-10-bonus--resisting-a-hostile-server-id-collision)).
See the [README's Status section](../../README.md#status) for exactly
what's in and out of scope at this stage.

## Didn't find your question?

[Open an issue](https://github.com/aranaisec-cyber/aran/issues) — usage
questions are welcome, not just bug reports.
