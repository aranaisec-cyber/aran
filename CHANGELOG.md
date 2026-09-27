# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); this project
doesn't yet follow strict semantic versioning (pre-1.0).

## [0.1.0] — Initial release

- Transparent MCP stdio proxy (`aran -- <command>`): wraps any downstream
  MCP server, no server-specific integration required.
- Output gate: blocks destructive outbound tool calls (`rm -rf`,
  `chmod 777`, fork bombs, curl/wget-pipe-to-shell, etc.) before they reach
  the real server.
- Input gate: redacts prompt-injection content in inbound responses before
  it reaches the agent, using a fail-closed default (redact unless a field
  is explicitly known protocol machinery, not the reverse).
- Hardened against an adversarial downstream server: id-collision bypasses,
  malformed/unexpected message shapes, batch-framed requests (including
  nested batches), non-UTF-8 encodings, and deeply-nested payloads are all
  covered by `tests/test_proxy_hostile.py` against
  `tests/fixtures/hostile_server.py`.
- Local JSONL audit log of every gated call (`~/.aran/audit.jsonl`).
- Signature set generated from a public labeled dataset via
  `scripts/sync_threat_intel.py`, with a minimum-length filter to reduce
  false positives from short, generic phrases.
- Packaged as an installable CLI (`pip install mcp-shield`), with the rule
  file shipped inside the wheel so a non-editable install still has the
  full signature set.
