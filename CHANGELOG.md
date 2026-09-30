# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); this project
doesn't yet follow strict semantic versioning (pre-1.0).

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
