# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); this project
doesn't yet follow strict semantic versioning (pre-1.0).

## [0.1.2] — 2026-09-30

- **Repositioned**: Aran is now introduced everywhere as "the lightweight,
  open-source developer framework for local IDE telemetry and local
  input/output guardrails" instead of "a transparent security proxy" /
  "wrapper" - the PyPI description, README, the marketing site, and the
  two agent-facing strings in `status.py`. Every mention of telemetry is
  explicit that it's local-only, never transmitted, to stay consistent
  with the project's zero-transmission stance.
- **Architecture diagram** in README.md: a Mermaid flowchart of the core
  request/response loop (IDE → outbound gate → real MCP server → inbound
  gate → IDE), with the blocked path and the audit log as dashed edges.
  Renders natively on GitHub, no image hosting.
- **Session-start self-description**: Aran appends a short paragraph to
  the `initialize` response's `instructions` field (MCP's own mechanism
  for text the client feeds to the model at connection time) explaining
  what a `-32001`/`-32002` blocked-call error and a
  `[Aran] content blocked: ...` result mean. Appended to, never replacing,
  whatever instructions the real server already provides. Always on, zero
  extra tool calls - the agent recognizes Aran's behavior correctly the
  first time it happens instead of misreading a block as a bug.
- **Personal allowlist** (`~/.aran/allowlist.yaml`, never touched by
  `scripts/sync_threat_intel.py`): `allowed_signatures` disables specific
  signatures by exact string (copy-paste a `matched_signature` value
  straight out of the audit log to silence a false positive for yourself,
  durably, without editing the shared rules file); `trusted_repos`
  (`owner/repo` or `owner/*`) skips the GitHub repo scan - and its network
  fetch - entirely for repos you already trust. A startup notice reports
  how many signatures were disabled when the file has entries.
- **`aran_explain` built-in tool**: ask whether a piece of text would be
  blocked or redacted, and by which signature, without sending it
  anywhere - a dry run against the same four signature categories the
  real gates use. Same self-answering pattern as `aran_status`: never
  forwarded to the wrapped server, spliced into `tools/list`.
- **`aran_status` gains `format: "json"`**: a machine-readable object
  (`active`, `mode`, `by_outcome`, `most_recent_non_clean_event`, ...) for
  scripts or CI checks to assert against, instead of parsing the
  plain-text summary.
- **Optional loop guard** (`ARAN_LOOP_GUARD=1`, off by default): blocks a
  tool call once the exact same call (same name, same arguments) repeats
  past a threshold (`ARAN_LOOP_GUARD_THRESHOLD`, default 20) within a
  tracking window (`ARAN_LOOP_GUARD_WINDOW_SECONDS`, default 60) -
  frequency-based, not content-based, for a stuck/looping agent hammering
  an otherwise-benign call. Blocked with `code: -32003`. Off by default
  because, unlike the content-based gates, a fast legitimate repeat
  (polling, an intentional retry) looks identical to a genuine loop by
  design. Aran's own `aran_status`/`aran_explain` calls are exempt.

## [0.1.1] — 2026-09-30

- **`aran_status` built-in tool**: ask your agent "what's aran's status?"
  and get a plain-text summary of recent gate activity (messages checked,
  blocked/redacted/errored, most recent non-clean event) directly in your
  chat - no need to open `~/.aran/audit.jsonl` yourself. Answered by Aran
  directly (never forwarded to the wrapped server) and spliced into
  `tools/list` responses so agents can discover it on their own. Optional
  `hours` argument narrows/widens the window (`0` = all-time). Always on,
  read-only, no network calls. Also fixed the README.md relative links
  that would 404 on the PyPI project page (they now point to absolute
  GitHub URLs).

## [0.1.0] — 2026-09-30 — Initial PyPI release

- Transparent MCP stdio proxy (`aran -- <command>`): wraps any downstream
  MCP server, no server-specific integration required.
- Output gate: blocks destructive outbound tool calls (`rm -rf`,
  `chmod 777`, fork bombs, curl/wget-pipe-to-shell, etc.) before they reach
  the real server. Blocked calls carry a JSON-RPC error (`code: -32001`)
  with `data` naming the violation, the matched signature, and a
  best-effort `target_node` for which argument matched.
- Input gate: redacts prompt-injection content in inbound responses before
  it reaches the agent, using a fail-closed default (redact unless a field
  is explicitly known protocol machinery, not the reverse).
- **Optional GitHub repo scan** (`ARAN_SCAN_GITHUB_REPOS=1`, off by
  default): when an outbound tool call references a public GitHub repo
  (an HTTPS or SSH clone URL, in any tool's arguments), Aran fetches that
  repo's tarball and scans it for destructive commands, prompt injection,
  hardcoded secrets, and supply-chain install/build hooks before the call
  that would clone/download it is forwarded. A match blocks the call with
  `code: -32002`. This is the one feature in Aran that makes outbound
  network requests, so it fails *open* (not closed) if the fetch itself
  can't complete — see `docs/guide/08-modes-and-configuration.md`.
- `ARAN_MODE=audit`: dry-run mode. Every gate decision still runs and is
  logged (as `would_block`), but nothing is actually blocked or redacted.
- `ARAN_PROFILE=1`: prints a timing/leaf-count line to stderr per gated
  message.
- Hardened against an adversarial downstream server: id-collision bypasses,
  malformed/unexpected message shapes, batch-framed requests (including
  nested batches), non-UTF-8 encodings, and deeply-nested payloads are all
  covered by `tests/test_proxy_hostile.py` against
  `tests/fixtures/hostile_server.py`.
- Local JSONL audit log of every gated call (`~/.aran/audit.jsonl`).
- Signature set generated from a public labeled dataset via
  `scripts/sync_threat_intel.py`, with a minimum-length filter to reduce
  false positives from short, generic phrases.
- Packaged as an installable CLI (`pip install aran`, or `uvx aran --`
  with zero install step), with the rule file shipped inside the wheel so
  a non-editable install still has the full signature set.
- `docs/guide/`: a full beginner's guide, one concept per page.
