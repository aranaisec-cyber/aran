# 4. Wiring Aran into Your IDE

Once Aran is [installed](02-installation.md), using it with a real IDE is
a one-line change to a config file you likely already have: wherever your
IDE currently launches an MCP server directly, you make it launch Aran
instead, with the original command moved after a `--`.

## The general pattern

Any MCP-speaking tool's config ultimately boils down to a `command` and a
list of `args` used to start the server. Before Aran:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
    }
  }
}
```

After — `command` becomes `aran`, and everything that used to be in
`command`/`args` moves into `args`, preceded by a literal `"--"`:

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

That's the whole integration. Nothing about the `filesystem` server
itself changes — it doesn't know Aran exists. Your IDE now starts Aran,
Aran starts the real server as its own child process, and every message
between the two is relayed through both gates on the way through.

If `aran` isn't resolving as a bare command (see
[2. Installation](02-installation.md#if-aran-isnt-found-on-your-path)),
use the fully-qualified form instead:

```json
{
  "command": "python",
  "args": ["-m", "aran.cli", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
}
```

## Claude Code

Claude Code auto-detects a project-root `.mcp.json` file and prompts you
to approve it the first time you open the project. This repository ships
one at [`.mcp.json`](../../.mcp.json), already wired to wrap
[`mcp-server-fetch`](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch)
(the official reference server for fetching web pages) through Aran:

1. Clone this repo (if you haven't already) and open it in Claude Code.
2. Claude Code will show a one-time approval prompt for the `aran-fetch`
   server defined in `.mcp.json`. Approve it.
3. It needs [`uv`](https://docs.astral.sh/uv/) installed (specifically the
   `uvx` command) — that's what actually fetches and runs
   `mcp-server-fetch`. No other per-user setup is required.

To wrap your **own** server instead of the fetch example, either edit
`.mcp.json` directly, or let Claude Code generate the entry for you:

```bash
claude mcp add <name> --scope project -- python -m aran.cli -- <your command> <your args...>
```

## Cursor

**One-click:** the *"Add to Cursor"* badge on the repo's
[README](../../README.md) installs the same `aran-fetch` example directly
— no manual JSON editing. It needs `uv`/`uvx` installed, same as the
Claude Code path above.

**Manual / your own server:** generate your own one-click link by
base64-encoding a small JSON config:

```json
{"command": "python", "args": ["-m", "aran.cli", "--", "<your command>", "<your args...>"]}
```

and placing that base64 string into:

```
cursor://anysphere.cursor-deeplink/mcp/install?name=<name>&config=<that base64>
```

Or skip the deep link entirely and add the same JSON shown in
"The general pattern" above directly to Cursor's MCP settings.

## Any other MCP-speaking tool

Windsurf and other IDEs that support MCP use the same `command`/`args`
JSON shape shown above — apply the same `command: "aran"`,
`args: ["--", ...original command...]` transformation in whatever
settings UI or config file that tool uses for MCP servers.

## Confirming Aran is actually running

A server showing as "connected" in your IDE only confirms the process
started — it doesn't by itself prove traffic is being gated (a server
launched directly, without Aran, would also show as connected).

### The easy way: just ask your agent

Aran answers a built-in tool call, `aran_status`, directly — it's never
forwarded to the wrapped server, so getting a real answer back *is* the
proof. In your IDE's chat, ask something like:

> *what's aran's status?*

Your agent should call `aran_status` and show you a plain-text reply
right there in the chat, similar to:

```
Aran is ACTIVE and enforcing.

Audit log: /home/you/.aran/audit.jsonl (12 entries total)

In the last 24 hours: 12 messages checked
  12 allowed

This response was answered directly by Aran - it was never forwarded to the wrapped server.
```

No log file to open, no terminal needed — this is designed specifically so
a developer doesn't have to dig through `~/.aran/audit.jsonl` themselves
just to confirm protection is active. If your agent doesn't have
`aran_status` in its tool list yet, it appears the moment your IDE next
calls `tools/list` on the wrapped server (Aran splices it into that
response) — restarting the MCP connection in your IDE forces that.

Optionally narrow or widen the window: ask *"what's aran's status over
the last hour?"* or *"...all time?"* — the agent passes that through as
the tool's `hours` argument (`0` means all-time).

### Your agent already knows about Aran, before you ask anything

Separately from `aran_status`, Aran appends a short paragraph to every
session's `initialize` response — MCP's own built-in mechanism for text
the client feeds to the model automatically, at connection time, before
any tool call happens. It explains what a `-32001`/`-32002` blocked-call
error means and that `[Aran] content blocked: ...` in a tool result is a
redaction, not a failure. This is what makes the agent recognize Aran's
behavior correctly *the first time it happens*, instead of misreading a
block as a bug and retrying, or stopping to ask you what went wrong —
zero extra round trips, since the context was already there. You don't
need to do anything for this — it's automatic and always on.

### The manual way: the audit log directly

If you'd rather look yourself, or want to confirm something `aran_status`'s
summary doesn't show (the exact `matched_signature` for a specific block,
for instance):

1. Ask your agent to use the wrapped tool for anything — list a
   directory, fetch a URL, whatever the server does.
2. Check `~/.aran/audit.jsonl` for a new line:

   ```bash
   tail -n 5 ~/.aran/audit.jsonl
   ```

   If you see fresh entries with a `timestamp` matching when you just
   asked your agent to act, Aran is in the path and gating traffic. If the
   file doesn't exist or has no new lines, your IDE is probably still
   launching the original server directly — double-check the `command`
   field actually says `aran` (or `uvx`, with `aran` as the first `args`
   entry), not the original server binary.

For the fetch-server example specifically: ask your agent to fetch a page
containing `ignore previous instructions` (or write a tiny local HTML file
with that phrase and fetch it) — you should see the injected text redacted
in your agent's context, and a `"blocked"` entry appear in the audit log.
This is the exact mechanism covered in depth in
[6. The Inbound Gate](06-inbound-gate.md), just exercised against a live
network fetch instead of the practice server.

## A note on the fetch-server example specifically

`mcp-server-fetch`'s own documentation notes it can reach local/internal
network addresses — a real consideration for any fetch-capable tool
regardless of Aran, worth knowing if you point it at anything beyond
public URLs.

## Next

- [5. The Outbound Gate](05-outbound-gate.md) and
  [6. The Inbound Gate](06-inbound-gate.md) — now that Aran is wired in,
  understand exactly what it's checking on every message.
- [10. Troubleshooting](10-troubleshooting.md) — if your server shows as
  errored or disconnected after wrapping it with Aran.
