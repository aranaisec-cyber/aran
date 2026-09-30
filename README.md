# Aran

[![CI](https://github.com/aranaisec-cyber/aran/actions/workflows/ci.yml/badge.svg)](https://github.com/aranaisec-cyber/aran/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/aranaisec-cyber/aran/blob/develop/LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://github.com/aranaisec-cyber/aran/blob/develop/pyproject.toml)
[![PyPI](https://img.shields.io/pypi/v/aran.svg)](https://pypi.org/project/aran/)
[![Add to Cursor](https://img.shields.io/badge/Cursor-Add_fetch_server-000000?logo=cursor&logoColor=white)](cursor://anysphere.cursor-deeplink/mcp/install?name=aran-fetch&config=eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyJhcmFuIiwiLS0iLCJ1dngiLCJtY3Atc2VydmVyLWZldGNoIl19)
[![Claude Code: .mcp.json included](https://img.shields.io/badge/Claude_Code-.mcp.json_included-5A32FB)](https://github.com/aranaisec-cyber/aran/blob/develop/.mcp.json)

A transparent security proxy for [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) stdio servers. Wraps any existing MCP server — no server-specific
integration — and gates traffic in both directions before it reaches your
agent or your machine:

- **Blocks dangerous outbound tool calls** — destructive commands (`rm -rf`,
  `chmod 777`, fork bombs, ...), before they ever reach the real server.
- **Redacts prompt-injection payloads in inbound tool results** — before
  they reach your agent's context window.
- **Audits every gated call** to a local JSONL log, so you can see what was
  blocked and tune false positives.

## Why

Autonomous coding agents (Claude Code, Cursor, Windsurf, ...) use MCP
servers to read files, run shell commands, and hit the network. If an agent
ingests untrusted content — a webpage, a repo file, a database row —
containing a hidden prompt injection, it can be manipulated into running
destructive commands or exfiltrating secrets, using your own valid
credentials. Static-analysis tools and traditional network firewalls are
both blind to this: neither operates at the live protocol layer where the
agent and its tools actually talk to each other.

Aran sits inline at that layer instead, as a stdio proxy your IDE launches
transparently.

**New to Aran?** [docs/guide/](https://github.com/aranaisec-cyber/aran/blob/develop/docs/guide/README.md) is a full,
beginner-friendly walkthrough — one concept per page, from "what is MCP"
through installing, wiring it into your IDE, and a hands-on session that
proves every gate case works, with real command output at each step. The
rest of this README is the fast, condensed version of the same
information.

## Install

Aran is on PyPI — no install step needed if your IDE launches it via
[`uvx`](https://docs.astral.sh/uv/) (recommended, see below). To use the
plain `aran` command yourself:

```bash
pip install aran
```

To work on Aran itself instead, install from source:

```bash
git clone https://github.com/aranaisec-cyber/aran.git
cd aran
pip install -e .
```

## Usage

Wrap the command you'd normally use to launch an MCP server, via `uvx` so
nothing needs installing up front:

```bash
uvx aran -- npx -y @modelcontextprotocol/server-filesystem /path/to/project
```

(If you installed Aran yourself with `pip install aran` above, drop the
`uvx ` prefix and just run `aran -- ...` directly — both forms work
identically.)

### Wiring into an MCP-speaking IDE

In your IDE's MCP server config, replace the server's `command`/`args` with
`uvx`/`aran`, moving the original command after a `--` separator.

**Claude Code / Cursor-style JSON config:**

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "uvx",
      "args": ["aran", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
    }
  }
}
```

That's the whole integration — no prior `pip install` needed, `uvx` fetches
Aran transparently the first time your IDE launches it. Aran spawns the
real server as a child process and relays every message between it and
your IDE, gating tool calls and tool results as they pass through —
nothing else in your IDE config changes, and the downstream server needs
no modification.

Every gated message (allowed or blocked) is logged to `~/.aran/audit.jsonl`.

### One-click / auto-config

Both badges above wrap a real, production MCP server —
[`mcp-server-fetch`](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch),
the official reference server for fetching web pages — not a toy demo.
It's a deliberate choice: fetching an untrusted URL and having whatever
text is on that page land in your agent's context is *exactly* the attack
this project defends against, so wrapping it is the most honest possible
demonstration of what Aran does. It needs [`uv`](https://docs.astral.sh/uv/)
installed (`uvx` specifically) and needs no per-user path or account setup
— it works identically for every developer who clicks it.

- **Cursor:** the *"Add to Cursor"* badge above installs `aran-fetch`
  directly — one click, no manual config.
- **Claude Code:** this repo ships a working
  [`.mcp.json`](https://github.com/aranaisec-cyber/aran/blob/develop/.mcp.json) at
  its root wrapping the same server. Claude Code auto-detects
  project-level `.mcp.json` files — clone this repo, open it in Claude
  Code, and you'll get a one-time approval prompt for `aran-fetch`. There's
  no click-to-install deep link for Claude Code (unlike Cursor, it doesn't
  have one), but `.mcp.json` is the equivalent "ships with the repo,
  auto-detected" mechanism.

Once it's running, ask your agent to fetch a URL and watch
`~/.aran/audit.jsonl` — every fetched page's content passes through the
input gate exactly like the manual tests in
[TESTING.md](https://github.com/aranaisec-cyber/aran/blob/develop/TESTING.md), just
against the live internet instead of a canned fixture. A page containing
`ignore previous instructions` (or anything else in
[`src/aran/default-rules.yaml`](https://github.com/aranaisec-cyber/aran/blob/develop/src/aran/default-rules.yaml))
gets redacted before your agent ever sees it.

To wrap a *different* server instead — your own, or another server
entirely — the pattern is identical: swap the args in `.mcp.json`, or
generate your own Cursor deep link by base64-encoding
`{"command":"uvx","args":["aran","--",<your command>,<your args...>]}`
and using it in
`cursor://anysphere.cursor-deeplink/mcp/install?name=<name>&config=<that base64>`
— or run `claude mcp add <name> --scope project -- uvx aran --
<your command> <your args...>`, which writes the `.mcp.json` entry for you.

**Heads up:** `mcp-server-fetch`'s own documentation notes it can reach
local/internal network addresses, which is a real consideration for any
fetch-capable tool regardless of Aran — worth knowing if you point it at
anything beyond public URLs.

## How it works

- **Outbound** (`tools/call` requests): the tool name and arguments are
  checked against a list of destructive-command signatures. A match means
  the call is never forwarded to the real server — Aran synthesizes a
  JSON-RPC error response instead.
- **Inbound** (tool results and other responses): every string is scanned
  for prompt-injection signatures. A match in agent-visible content gets
  replaced with a redaction notice before being relayed; a small, explicit
  set of protocol-machinery fields (`protocolVersion`, `serverInfo`,
  resource `uri`s, etc.) is exempt from rewriting so a match there doesn't
  break session negotiation — see
  [the design spec](https://github.com/aranaisec-cyber/aran/blob/develop/docs/superpowers/specs/2026-09-26-mcp-protocol-proxy-design.md#32-message-flow)
  for the exact field list and reasoning.
- Aran treats the downstream server it wraps as **untrusted** — the gating
  guarantees are designed to hold even against a malformed or actively
  hostile server, not just a well-behaved one. See
  [`tests/fixtures/hostile_server.py`](https://github.com/aranaisec-cyber/aran/blob/develop/tests/fixtures/hostile_server.py)
  and
  [`tests/test_proxy_hostile.py`](https://github.com/aranaisec-cyber/aran/blob/develop/tests/test_proxy_hostile.py)
  for the adversarial test suite this is verified against.
- A blocked outbound call gets a JSON-RPC error with `code: -32001` and a
  `data` field giving the violation, the matched signature, and a
  best-effort `target_node` (which argument the match was found in) —
  useful context for an agent or developer debugging why a call was
  blocked. A bare `-32000` with no `data` means Aran itself couldn't
  safely inspect the message (fail-closed), not a signature match.
- **Optional: scan a public GitHub repo before it's cloned/downloaded**
  (`ARAN_SCAN_GITHUB_REPOS=1`). If an outbound call references a
  `github.com` repo (an HTTPS clone URL or an SSH remote, in any tool's
  arguments — not tied to a specific tool name), Aran fetches that repo's
  tarball and scans every file against destructive-command,
  prompt-injection, hardcoded-secret, and supply-chain
  (`curl | bash`-style install hooks) signatures *before* the call that
  would clone it is forwarded. A match blocks the call with
  `code: -32002`. This is the one feature in Aran that makes outbound
  network requests, so it's off by default — see
  [Configuration](#configuration) below.

## Configuration

Environment variables, read once at startup:

- **`ARAN_MODE=audit`** — dry-run mode. Gate decisions still run and are
  still logged (as `would_block` instead of `blocked`), but nothing is
  actually blocked or redacted — every call and response is forwarded
  unmodified. Use this to tune signatures against real traffic before
  turning enforcement on.
- **`ARAN_PROFILE=1`** (or `true`/`yes`/`on`) — prints a timing line to
  stderr for every gated message: how long the outbound check took, and
  how many JSON leaf nodes the inbound scan visited and in how long.
- **`ARAN_SCAN_GITHUB_REPOS=1`** (or `true`/`yes`/`on`) — enables the
  GitHub repo scan described above. Prints a one-time startup notice,
  since this is the only toggle that makes Aran reach the network. If the
  fetch itself fails (offline, rate-limited, repo not found, ...), the
  call is forwarded anyway — a failed scan is logged as `"error"`, not
  treated as a match; see
  [docs/guide/08-modes-and-configuration.md](https://github.com/aranaisec-cyber/aran/blob/develop/docs/guide/08-modes-and-configuration.md#optional-aran_scan_github_repos1--scan-a-repo-before-its-cloned)
  for the full reasoning on why this one check fails open instead of
  closed.

```bash
ARAN_MODE=audit aran -- npx -y @modelcontextprotocol/server-filesystem /path
ARAN_SCAN_GITHUB_REPOS=1 aran -- npx -y @modelcontextprotocol/server-filesystem /path
```

See [TESTING.md](https://github.com/aranaisec-cyber/aran/blob/develop/TESTING.md#step-3f-observability--aran_modeaudit-and-aran_profile)
for worked examples of `ARAN_MODE`/`ARAN_PROFILE`.

## Rule config

Signatures live in `src/aran/default-rules.yaml`, which ships inside
the installed package, under four keys: `input_gate_signatures` and
`output_gate_signatures` (the two live gates, described above) plus
`secret_signatures` and `supply_chain_signatures` (used only by the
optional GitHub repo scan). The latter two are optional in a hand-edited
rules file — an older file that predates them loads exactly as before,
falling back to a small built-in default for whichever it's missing, with
no warning. Refresh the prompt-injection and destructive-command
signatures from a live labeled dataset with:

```bash
python scripts/sync_threat_intel.py
```

**On false positives:** the shipped signature set is generated from a
public labeled dataset and, like any pattern-based detector, can flag
benign content. If something gets redacted/blocked that shouldn't be,
please [open an issue](https://github.com/aranaisec-cyber/aran/issues/new?template=false_positive.yml) with
the matched signature (visible in the audit log) and the offending text.

## Security

This is a security tool — please report vulnerabilities responsibly. See
[SECURITY.md](https://github.com/aranaisec-cyber/aran/blob/develop/SECURITY.md) for scope and reporting instructions.

## Development

```bash
git clone https://github.com/aranaisec-cyber/aran.git
cd aran
pip install -e ".[dev]"
pytest -v
```

See [CONTRIBUTING.md](https://github.com/aranaisec-cyber/aran/blob/develop/CONTRIBUTING.md)
for project layout and testing philosophy, and
[TESTING.md](https://github.com/aranaisec-cyber/aran/blob/develop/TESTING.md)
for a step-by-step manual verification procedure — including seeing the
output/input gates block a destructive command and redact an injection
payload live, not just watching `pytest` pass.

## Status

Early (v0.1, pre-1.0). The core proxy — invocation, bidirectional gating,
YAML config, audit log — is implemented and tested, including against an
adversarial downstream-server test suite. Not yet covered: a multi-server
gateway, enterprise/compliance features, and a hosted control plane — see
the [design spec](https://github.com/aranaisec-cyber/aran/blob/develop/docs/superpowers/specs/2026-09-26-mcp-protocol-proxy-design.md#2-scope)
for what's explicitly in and out of scope for this stage.

## License

[MIT](https://github.com/aranaisec-cyber/aran/blob/develop/LICENSE)
