# Aran — MCP Shield

[![CI](https://github.com/REPLACE_ME/mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/REPLACE_ME/mcp-shield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

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
pip install mcp-shield
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

Signatures live in `src/mcp_shield/default-rules.yaml`, which ships inside
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
git clone https://github.com/REPLACE_ME/mcp-shield.git
cd mcp-shield
pip install -e ".[dev]"
pytest -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for project layout and testing
philosophy.

## Status

Early (v0.1, pre-1.0). The core proxy — invocation, bidirectional gating,
YAML config, audit log — is implemented and tested, including against an
adversarial downstream-server test suite. Not yet covered: a multi-server
gateway, enterprise/compliance features, and a hosted control plane — see
the [design spec](docs/superpowers/specs/2026-09-26-mcp-protocol-proxy-design.md#2-scope)
for what's explicitly in and out of scope for this stage.

## License

[MIT](LICENSE)
