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

**One interaction to know about:** if `ARAN_SCAN_GITHUB_REPOS=1` is also
set (see below) and a call references a GitHub repo, the outbound timing
line includes that scan's network fetch time too — a call that clones a
repo can legitimately show hundreds of milliseconds where an ordinary
call shows one or two. That's the network round-trip, not a regression in
the signature check itself.

Both `ARAN_MODE` and `ARAN_PROFILE` are independent and combine freely:

```bash
ARAN_MODE=audit ARAN_PROFILE=1 aran -- <your command>
```

Both are read **once, at startup, from the environment Aran itself was
launched with** — the downstream server you're wrapping has no way to set
or influence either one. The same is true of the third toggle below.

## Optional: `ARAN_SCAN_GITHUB_REPOS=1` — scan a repo before it's cloned

Everything else in this guide runs entirely offline — Aran inspects
messages it already has in hand and never makes a network call of its
own. This one feature is the deliberate exception.

**What it does:** if an outbound tool call references a public GitHub
repo anywhere in its arguments — an HTTPS clone URL
(`https://github.com/owner/repo`) or an SSH remote
(`git@github.com:owner/repo.git`), in *any* tool's arguments, not tied to
a specific tool name like `git_clone` — Aran downloads that repo's
tarball and scans every text file in it against four signature
categories **before** the call that would clone/download it is allowed
through:

- **Destructive commands** — the same category the
  [outbound gate](05-outbound-gate.md) already checks live tool calls
  against, applied here to a repo's own install/build scripts.
- **Prompt injection** — the same category the
  [inbound gate](06-inbound-gate.md) checks tool results against; a
  repo's README or docs can carry a payload aimed at whatever agent reads
  it later (e.g. during a code review), not just a live tool response.
- **Hardcoded secrets** — a new category specific to this scan: AWS
  access keys, GitHub tokens, Slack tokens, Google API keys,
  OpenAI-style keys, and PEM private key blocks accidentally committed to
  the repo.
- **Supply-chain install hooks** — also new: patterns like
  `curl ... | bash`, a base64-decode-then-execute pipeline, or a
  PowerShell download cradle, found specifically in the repo's own
  content (as opposed to the destructive-command category, which is
  about a command's *effect*, this one is about install/build tooling
  fetching and running code from the network).

A match blocks the call with a JSON-RPC error, `code: -32002`, and
`data` giving the repo, the specific file, the category, and the matched
signature — the same shape as the outbound gate's `-32001` error (see
[5. The Outbound Gate](05-outbound-gate.md)), just for a problem found in
the *referenced repo's content* rather than in the call's own arguments.

**Why it's off by default:** every other check in Aran is a local pattern
match with no network involved — a core part of what makes the "zero
network calls, nothing sent anywhere" claim in the
[FAQ](11-faq.md#does-aran-send-any-data-anywhere) true. This feature
necessarily breaks that, since scanning a repo's *content* means
downloading it first. Enabling it is an explicit choice:

```bash
ARAN_SCAN_GITHUB_REPOS=1 aran -- npx -y @modelcontextprotocol/server-filesystem /path
```

Aran prints a one-time startup notice specifically because this is the
one toggle that changes that network posture:

```
[Aran] GitHub repo scan enabled (ARAN_SCAN_GITHUB_REPOS=1): an outbound call referencing a public GitHub repo will have that repo fetched and scanned before being forwarded - this makes network requests to GitHub
```

**Why a failed scan fails OPEN, not closed:** every other failure mode in
Aran is fail-*closed* — if Aran can't safely inspect a message, it blocks
it (see [5. The Outbound Gate § -32000 vs -32001](05-outbound-gate.md#-32000-vs--32001--two-different-kinds-of-not-forwarded)).
This check is the one deliberate exception. If the fetch itself fails —
you're offline, GitHub is rate-limiting unauthenticated requests, the
repo doesn't exist or is private, the archive is corrupt — that failure
is logged with `"outcome": "error"` and a stderr warning, but **the call
is still forwarded**. The reasoning: this is a best-effort *external*
lookup Aran does not control, not Aran's own ability to inspect a
message it already has. Failing closed here would mean every clone
breaks the moment GitHub is briefly unreachable, for a check that's
opt-in and advisory in the first place — that's a worse tradeoff than
occasionally proceeding without the extra check.

**Worked example — a repo with a destructive install script gets
blocked:**

```bash
printf '%s\n' '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "git clone https://github.com/some-org/some-repo.git"}}}' \
  | ARAN_SCAN_GITHUB_REPOS=1 python -m aran.cli -- python tests/fixtures/fake_server.py
```

If `some-repo` contains a file matching any of the four categories above,
you'll see (paraphrased):

```json
{"jsonrpc": "2.0", "id": 1, "error": {"code": -32002, "message": "[Aran] blocked: outbound call references GitHub repo some-org/some-repo, which failed a content scan (...)", "data": {"violation": "GitHub repo content scan matched", "repo": "some-org/some-repo", "file": "install.sh", "category": "destructive_command", "matched_signature": "..."}}}
```

and the audit log gets an entry with an extra `detail` field (the only
place in the audit log this appears — see
[7. The Audit Log](07-audit-log.md)):

```json
{"timestamp": "...", "direction": "outbound", "tool_name": "run_command", "outcome": "blocked", "matched_signature": "rm\\s+-[rfRF]+", "detail": {"repo": "some-org/some-repo", "file": "install.sh", "category": "destructive_command", "files_scanned": 12}}
```

A clean repo, or the same call with `ARAN_SCAN_GITHUB_REPOS` unset,
forwards exactly as it always did — this feature costs nothing for the
overwhelming majority of tool calls that never reference a GitHub repo at
all, and is fully inert unless you turn it on.

## Optional: `ARAN_LOOP_GUARD=1` — block a runaway/looping agent

Every check elsewhere in this guide is **content**-based — it looks at
*what* a call or response contains. This one is different: it's
**frequency**-based. It doesn't care what a tool call contains, only that
the exact same call (same tool name, same arguments) is repeating fast.

**What it does:** once the identical call has happened
`ARAN_LOOP_GUARD_THRESHOLD` times (default **20**) within
`ARAN_LOOP_GUARD_WINDOW_SECONDS` (default **60**), every further repeat
of that same call is blocked with a JSON-RPC error, `code: -32003`, until
the window ages out. Two calls with the same tool name but *different*
arguments are tracked completely separately — this only catches a call
repeating with the same arguments, not normal varied tool use.

```bash
ARAN_LOOP_GUARD=1 aran -- npx -y @modelcontextprotocol/server-filesystem /path
# tune the threshold/window:
ARAN_LOOP_GUARD=1 ARAN_LOOP_GUARD_THRESHOLD=10 ARAN_LOOP_GUARD_WINDOW_SECONDS=30 aran -- ...
```

**Why it's off by default:** every other check in this guide is
content-based, so a legitimate message never trips it by accident — the
signature either matches dangerous content or it doesn't. Frequency is
different: a fast, *intentional* repeat (polling a status endpoint,
retrying a flaky network call a few times) looks structurally identical
to a genuine stuck loop. Getting that distinction wrong blocks something
that was never dangerous, so — like the GitHub repo scan, for a different
reason — this needs an explicit opt-in rather than being on by default.

**Worked example** — five identical calls, threshold set to 3:

```bash
printf '%s\n%s\n%s\n%s\n%s\n' \
  '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}}' \
  '{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}}' \
  '{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}}' \
  '{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}}' \
  '{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}}' \
  | ARAN_LOOP_GUARD=1 ARAN_LOOP_GUARD_THRESHOLD=3 python -m aran.cli -- python tests/fixtures/fake_server.py
```

Calls 1 and 2 come back clean; call 3 (the threshold) and every call
after it come back blocked:

```json
{"jsonrpc": "2.0", "id": 3, "error": {"code": -32003, "message": "[Aran] blocked: 3 identical calls to 'list_files' within 60s - possible runaway loop", "data": {"violation": "repeated identical call - possible runaway loop", "tool_name": "list_files", "count": 3, "window_seconds": 60.0}}}
```

Aran's own `aran_status` and `aran_explain` calls are exempt — they're
answered before this check ever runs, so asking `aran_status` several
times in a row while debugging never trips it.

## `ARAN_APPROVALS` / `ARAN_APPROVAL_DIALOG` — human approval of blocked calls

On by default: an outbound block (`-32001`, `-32002`) carries an approval code, and you can approve or decline that exact call from a desktop dialog or `aran approve CODE`. `ARAN_APPROVALS=0` (or `false`/`off`/`no`) turns it off, restoring plain blocks. `ARAN_APPROVAL_DIALOG=0` keeps approval but never opens a desktop dialog (terminal-only). Full explanation, including why the agent can't approve its own call: [12. Human Approval](12-approvals.md).

## The personal allowlist: `~/.aran/allowlist.yaml`

No environment variable enables this — it's a plain YAML file you create
yourself. Unlike the rules file, nothing ships it, nothing ever
overwrites it (`scripts/sync_threat_intel.py` never touches it), and its
absence is completely normal — most developers will never create one.

```yaml
allowed_signatures:
  - "rm\\s+-[rfRF]+"     # the exact matched_signature text, copied from the audit log
trusted_repos:
  - octocat/demo          # owner/repo, exact
  - my-org/*               # every repo under an owner
```

**`allowed_signatures`** — disables specific signatures by their exact
source string, across all four categories (destructive-command,
prompt-injection, secret, supply-chain). The intended workflow: something
gets blocked or redacted, you decide it's a false positive, you find its
`matched_signature` value in `~/.aran/audit.jsonl` (see
[7. The Audit Log](07-audit-log.md)), and you paste that exact string
into this list. Matching is exact-string, not fuzzy — this is deliberate,
so you never accidentally disable more than you meant to.

When the file has entries, Aran prints a one-time startup notice:

```
[Aran] 1 signature(s) disabled by /home/you/.aran/allowlist.yaml (personal allowlist)
```

**`trusted_repos`** — only matters when `ARAN_SCAN_GITHUB_REPOS=1` is
also set. A repo listed here (or matched by an `owner/*` wildcard) skips
the content scan **and its network fetch** entirely — not "scanned and
found clean," but never fetched at all. This is the one entry in this
whole file that actually saves latency, not just changes a verdict. The
audit log records this distinctly (`"reason": "trusted_repos allowlist -
scan skipped"`) so it's never confused with a real scan result.

## The rules file

The actual signatures every check above uses live in a YAML file shipped
inside the installed package:
[`src/aran/default-rules.yaml`](../../src/aran/default-rules.yaml). It has
four top-level keys:

```yaml
input_gate_signatures:
  - "ignore previous instructions"
  - "system override"
  # ... hundreds more, one prompt-injection phrasing per line

output_gate_signatures:
  - "rm\\s+-[rfRF]+"
  - "chmod\\s+777"
  # ... destructive command patterns

secret_signatures:
  - "AKIA[0-9A-Z]{16}"
  # ... hardcoded-credential patterns, used only by the GitHub repo scan

supply_chain_signatures:
  - "curl\\s+.*\\|\\s*(sh|bash|python[0-9.]*)"
  # ... install/build-hook patterns, also used only by the GitHub repo scan
```

- `input_gate_signatures` feeds [the inbound gate](06-inbound-gate.md).
- `output_gate_signatures` feeds [the outbound gate](05-outbound-gate.md).
- `secret_signatures` and `supply_chain_signatures` feed the optional
  [GitHub repo scan](#optional-aran_scan_github_repos1--scan-a-repo-before-its-cloned)
  above — inert unless `ARAN_SCAN_GITHUB_REPOS=1` is set.

If this file is ever missing, unreadable, not valid YAML, or has a
malformed value for `input_gate_signatures`/`output_gate_signatures`,
Aran does **not** crash and does **not** fail open — it falls back to a
small built-in default list and prints a one-time warning to stderr
telling you exactly which key fell back and why. The two repo-scan keys
are treated a little differently, since they're newer and optional: a
rules file that simply doesn't have them yet (any file written before
this feature existed) loads silently, with no warning, falling back to
their own small built-in defaults — only a key that's *present but
malformed* triggers a warning for those two. See
[10. Troubleshooting](10-troubleshooting.md#rules-file-warning) if you see
this warning.

### Refreshing the signature set

The prompt-injection and destructive-command signatures are generated
from a live, labeled public dataset (the secret/supply-chain lists are
hand-maintained, since there's no equivalent live feed for those). To
pull the latest version:

```bash
python scripts/sync_threat_intel.py
```

This overwrites `src/aran/default-rules.yaml` with a fresh signature list
for all four keys. Review the diff before committing if you're
maintaining a fork with local customizations.

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
