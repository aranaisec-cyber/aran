# Aran — MCP Shield

A transparent security proxy for [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) stdio servers. Wraps any existing MCP server, blocking dangerous
outbound tool calls (destructive commands, path traversal, exfil patterns)
and redacting prompt-injection payloads in inbound tool results, before
either reaches your agent or your machine.

## Install

```bash
pip install -e ".[dev]"
```

## Usage

Wrap the command you'd normally use to launch an MCP server:

```bash
aran -- npx -y @modelcontextprotocol/server-filesystem /path/to/project
```

### Wiring into an MCP-speaking IDE

In your IDE's MCP server config, replace the server's `command`/`args` with
`aran`, moving the original command after a `--` separator. For example, in
a Claude Code / Cursor-style JSON config:

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

Aran spawns the real server as a child process and relays every message
between it and your IDE, gating tool calls and tool results as they pass
through. Every gated message is logged to `~/.aran/audit.jsonl`.

## Rule config

Signatures live in `config/default-rules.yaml`. Refresh the prompt-injection
signatures from a live labeled dataset with:

```bash
python scripts/sync_threat_intel.py
```

## Tests

```bash
pytest
```
