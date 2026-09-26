# Aran — Native MCP Protocol Proxy: Design Spec

Date: 2026-09-26
Status: Approved (v1 scope)

## 1. Objective & Thesis

Aran is an open-core security gateway for autonomous AI coding agents (Cursor,
Claude Code, Windsurf, etc.) that speak the Model Context Protocol (MCP).

Agents use MCP servers to read files, run shell commands, and hit network
endpoints. If an agent ingests untrusted content (a webpage, a repo file, a
database row) containing a hidden prompt injection, it can be manipulated into
running destructive commands or exfiltrating secrets — using the developer's
own valid credentials. Legacy static-analysis security tools (Snyk, Veracode,
SonarQube) and traditional network firewalls are both blind to this: they
don't operate at the live protocol layer where the agent and its tools
actually talk to each other.

Aran sits inline as a transparent proxy at that protocol layer, inspecting
every tool call and every tool result flowing between the IDE/agent and a
real MCP server, and blocking the ones that match known attack signatures —
before they reach the local filesystem/shell or the agent's context window.

## 2. Scope

### In scope (this spec, v1)
- A generic MCP stdio proxy that wraps any existing downstream MCP server.
- An output gate that blocks dangerous outbound tool calls (destructive
  commands, path traversal, known exfil patterns).
- An input gate that blocks/redacts prompt-injection content coming back in
  tool results, before it reaches the agent's context.
- A local YAML rule config (reusing the existing `config/default-rules.yaml`
  shape).
- A local JSONL audit log of every intercepted call.
- Packaging as an installable CLI (`aran -- <downstream command...>`).

### Explicitly out of scope (backlog, future specs)
- The multi-tenant enterprise cloud sandbox and EU AI Act compliance
  automation/dashboard described in the company's pitch materials. This is a
  large, separate subsystem (multi-tenancy, hosted infra, centralized
  governance UI) and is deferred until there's validated demand from design
  partners, per the founder's own "Feature Blocklist" / 5-minute-TTV rule.
- The GTM/lead-gen terminal nudge ("visit mcp-shield.com" on detecting
  enterprise usage). Not a security feature; revisit once the core proxy is
  stable.
- The config-driven multi-server gateway (one process multiplexing many
  downstream servers behind one endpoint). The generic single-server CLI
  wrapper is the smallest useful primitive and this can be layered on top of
  it later without a rewrite.
- Fixing the placeholder/broken threat-intel feed URLs in
  `scripts/sync_threat_intel.py` (`https://raw.githubusercontent.com` with no
  path). Tracked separately — v1 ships with the hardcoded baseline signatures
  already present in that script and `config/default-rules.yaml`.

### Existing prototype
`mcp_security_proxy.py` (a FastAPI HTTP proxy exposing `/v1/secure/input` and
`/v1/secure/execute`) predates this design and used a different integration
model (manual HTTP calls vs. native protocol-layer interception). It's
superseded by the architecture below. It is left in place for reference and
not deleted as part of this work; it can be removed in a later cleanup once
the new proxy is functional.

## 3. Architecture

### 3.1 Invocation model
Aran is invoked as a wrapper around the real MCP server's launch command:

```
aran -- <command to launch the real downstream MCP server>
```

In the IDE's MCP server config, the user replaces the server's `command`
with `aran`, and moves the original command + args after a `--` separator.
Aran spawns that real command as a child process and takes over relaying its
stdio to the parent (the IDE).

This generalizes to any existing MCP stdio server with no server-specific
code, and is the standard pattern used by comparable MCP security wrappers.

### 3.2 Message flow
Two independent async pumps relay JSON-RPC messages between the IDE (parent
stdin/stdout) and the wrapped server (child stdin/stdout):

**Client → Server (outbound):**
- Pass through all non-`tools/call` messages (`initialize`, `tools/list`,
  notifications, etc.) unmodified.
- For `tools/call` requests: serialize the tool name + arguments and run them
  through the **output gate** (regex signatures for destructive commands,
  path traversal, exfil-domain patterns).
- If blocked: the request is **never forwarded** to the real server. Aran
  synthesizes a JSON-RPC error response (reusing the original request's
  `id`) and writes it directly back to the IDE.
- If allowed: forward unmodified to the child process.
- Batch arrays (including nested ones) are unwrapped and each element gated on
  its own, so batch framing cannot carry a `tools/call` past the gate; blocked
  elements are stripped and answered individually, and the rest of the batch is
  forwarded with its framing intact.

**Server → Client (inbound):**
- Pass through all non-tool-result messages unmodified.
- For `tools/call` results: run the textual content of the result through the
  **input gate** (prompt-injection regex signatures).
- If a signature matches: replace the matched content with a placeholder
  (`[Aran] content blocked: flagged as a probable prompt injection`) before
  relaying to the IDE. The agent never sees the raw payload.
- If clean: forward unmodified.

Every message evaluated by either gate (allowed or blocked) is appended to
the audit log (§3.4) regardless of outcome.

**Deviation from the above, as implemented:** the input gate scans **every
inbound response**, not only results for `tools/call` requests Aran is tracking.
Making a tracked request id (or the absence of a `method` key, or the message
being a top-level object rather than a batch array) the precondition for gating
gave a hostile server several cheap ways to have content relayed un-gated - id
collisions, a spurious early response for a pending id, `"method": null`
alongside a real `result`, or a one-element JSON-RPC batch array. A message is
now gated whenever it carries a `result` or an `error` member, wherever it sits;
genuine server-originated requests and notifications carry neither and are still
passed through unmodified. Batch arrays are unwrapped (including nested ones)
and their response-shaped elements gated individually, with the framing left
intact.

Every string leaf of a gated response is scanned, and a match is **rewritten**
with the redaction notice **unless the field it sits in is protocol machinery**.
Listing the content-bearing fields instead (an allowlist of exact paths) was
fail-open by construction: fields nobody enumerated - `result.instructions`, a
tool's `inputSchema` parameter `description`s - were relayed verbatim, and a
hostile server could evade redaction just by sending content in an unexpected
shape (`content` as a bare string, `contents` as a list of strings,
`messages[*].content` as a list, `tools` as an object). The rule is therefore
inverted: redact by default, and exempt only a short denylist of machinery
**field names**, matched at any depth rather than by path, so the decision does
not depend on a shape the server controls. Exempt: `protocolVersion`,
`nextCursor`/`cursor`, `uri`/`uriTemplate`, `mimeType`, `blob`, `type`, `role`,
everything at or under `capabilities`, `serverInfo` and `_meta`, `error.code`,
and `name` where it identifies something the client addresses by name (a tool,
prompt, resource, template or prompt argument). A match in an exempt field is
recorded in the audit log for tuning while the value is relayed verbatim,
because rewriting protocol machinery broke session/capability negotiation and
destroyed unrelated tools' metadata without protecting the agent. Everything
else - `description`, `title`, `instructions`, `text`, `data`, structured tool
output, a content block's display `name`, and any field not yet invented - is
content and is redacted on a match.

### 3.3 Config
Rule signatures are loaded once at startup from
`config/default-rules.yaml`, reusing its existing shape:

```yaml
input_gate_signatures:
  - "<regex pattern checked against inbound tool-result text>"

output_gate_signatures:
  - "<regex pattern checked against outbound tool name + argument text>"
```

### 3.4 Audit log
Every intercepted call (allowed or blocked) is appended as one JSON line to
a local audit log file: timestamp, direction, tool name, matched signature
(if any), and outcome. This is a local file only in v1 — no upload, no
centralized collection — but gives a concrete audit trail that a future
compliance-reporting feature could read from.

### 3.5 Packaging
A Python package with a console-script entry point so it can be installed
and invoked as `aran -- <command...>`. The underlying package/module names
stay technical (`mcp_shield` / `mcp-shield`) — company branding ("Aran")
appears in user-facing text (banners, log messages, CLI help) but not in
importable identifiers, matching the founder's direction to leave existing
directory/package names alone.

## 4. Testing
Extend the existing adversarial test pattern (`tests/test_security_gates.py`)
to cover the new proxy behavior specifically:
- Output gate blocks known destructive commands/paths and does not forward
  them to a (test-double) downstream server.
- Input gate replaces known injection payloads in a tool result before it
  reaches the (test-double) client, and leaves clean content untouched.
- Non-tool-call messages pass through both directions unmodified.
- A blocked call produces a well-formed JSON-RPC error reusing the original
  request id.
- Audit log gets exactly one entry per gate-evaluated message.

## 5. Open follow-ups (not blocking v1)
- Real threat-intel feed URLs for `scripts/sync_threat_intel.py`.
- Decision on whether `mcp_security_proxy.py` (HTTP prototype) is removed or
  kept as an alternate integration path.
- Company/product naming: "Aran" is the company name; product/technical
  identifiers remain `mcp_shield`/`mcp-shield` unless a rename is explicitly
  requested later.
