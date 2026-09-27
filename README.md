# Aran

[![CI](https://github.com/REPLACE_ME/aran/actions/workflows/ci.yml/badge.svg)](https://github.com/REPLACE_ME/aran/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Add to Cursor](https://img.shields.io/badge/Cursor-Add_demo_server-000000?logo=cursor&logoColor=white)](cursor://anysphere.cursor-deeplink/mcp/install?name=aran-demo&config=eyJjb21tYW5kIjoicHl0aG9uIiwiYXJncyI6WyItbSIsImFyYW4uY2xpIiwiLS0iLCJweXRob24iLCJ0ZXN0cy9maXh0dXJlcy9mYWtlX3NlcnZlci5weSJdfQ==)
[![Claude Code: .mcp.json included](https://img.shields.io/badge/Claude_Code-.mcp.json_included-5A32FB)](.mcp.json)

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

## Install

```bash
pip install aran
```

(Not yet published to PyPI? Install from source: see
[Development](#development) below.)

## Usage

Wrap the command you'd normally use to launch an MCP server:

```bash
aran -- npx -y @modelcontextprotocol/server-filesystem /path/to/project
```

### Wiring into an MCP-speaking IDE

In your IDE's MCP server config, replace the server's `command`/`args` with
`aran`, moving the original command after a `--` separator.

**Claude Code / Cursor-style JSON config:**

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "aran",
      "args": ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
    }
  }
}
```

That's the whole integration. Aran spawns the real server as a child
process and relays every message between it and your IDE, gating tool calls
and tool results as they pass through — nothing else in your IDE config
changes, and the downstream server needs no modification.

Every gated message (allowed or blocked) is logged to `~/.aran/audit.jsonl`.

### One-click / auto-config

Both are honest about what they actually do — one installs with a click,
the other auto-detects with a one-time approval prompt:

- **Cursor:** the *"Add to Cursor"* badge above installs a demo server —
  Aran wrapping this repo's own test fixture
  (`tests/fixtures/fake_server.py`, no Node.js/network required) — so you
  can click it, open this cloned repo in Cursor, and immediately try
  Step 3 of [TESTING.md](TESTING.md) with zero manual config. To wrap a
  *real* server instead, generate your own deep link the same way:
  base64-encode `{"command":"python","args":["-m","aran.cli","--",<your
  command>,<your args...>]}` and use it in
  `cursor://anysphere.cursor-deeplink/mcp/install?name=<name>&config=<that base64>`.
- **Claude Code:** this repo ships a working [`.mcp.json`](.mcp.json) at
  its root, wrapping the same test fixture. Claude Code auto-detects
  project-level `.mcp.json` files — clone this repo, open it in Claude
  Code, and you'll get a one-time approval prompt for the `aran-demo`
  server. There's no click-to-install deep link for Claude Code (unlike
  Cursor, it doesn't have one), but `.mcp.json` is the equivalent
  "ships with the repo, auto-detected" mechanism. To wrap a real server in
  your own project, copy `.mcp.json`'s shape and swap in your command —
  or run `claude mcp add <name> --scope project -- python -m aran.cli --
  <your command> <your args...>`, which writes the same file for you.

Both of the above wrap the bundled test fixture specifically so the badge
and the `.mcp.json` in this repo work immediately for anyone who clones it
— no MCP server install, no path to edit. Swapping in your own server
after that is the one-line change shown in both bullets above.

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
  [the design spec](docs/superpowers/specs/2026-09-26-mcp-protocol-proxy-design.md#32-message-flow)
  for the exact field list and reasoning.
- Aran treats the downstream server it wraps as **untrusted** — the gating
  guarantees are designed to hold even against a malformed or actively
  hostile server, not just a well-behaved one. See
  [`tests/fixtures/hostile_server.py`](tests/fixtures/hostile_server.py) and
  [`tests/test_proxy_hostile.py`](tests/test_proxy_hostile.py) for the
  adversarial test suite this is verified against.

## Rule config

Signatures live in `src/aran/default-rules.yaml`, which ships inside
the installed package. Refresh the prompt-injection signatures from a live
labeled dataset with:

```bash
python scripts/sync_threat_intel.py
```

**On false positives:** the shipped signature set is generated from a
public labeled dataset and, like any pattern-based detector, can flag
benign content. If something gets redacted/blocked that shouldn't be,
please [open an issue](../../issues/new?template=false_positive.yml) with
the matched signature (visible in the audit log) and the offending text.

## Security

This is a security tool — please report vulnerabilities responsibly. See
[SECURITY.md](SECURITY.md) for scope and reporting instructions.

## Development

```bash
git clone https://github.com/REPLACE_ME/aran.git
cd aran
pip install -e ".[dev]"
pytest -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for project layout and testing
philosophy, and [TESTING.md](TESTING.md) for a step-by-step manual
verification procedure — including seeing the output/input gates block a
destructive command and redact an injection payload live, not just watching
`pytest` pass.

## Status

Early (v0.1, pre-1.0). The core proxy — invocation, bidirectional gating,
YAML config, audit log — is implemented and tested, including against an
adversarial downstream-server test suite. Not yet covered: a multi-server
gateway, enterprise/compliance features, and a hosted control plane — see
the [design spec](docs/superpowers/specs/2026-09-26-mcp-protocol-proxy-design.md#2-scope)
for what's explicitly in and out of scope for this stage.

## License

[MIT](LICENSE)
