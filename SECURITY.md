# Security Policy

Aran is a security tool: bugs here have outsized consequences, and we'd
rather hear about them privately than have them discovered by exploitation.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Instead, use GitHub's private vulnerability reporting:
[open a draft security advisory](../../security/advisories/new) on this
repository. If that's unavailable to you, email the maintainers directly
(see the repository's contact information) with:

- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal hostile MCP server payload is ideal, given
  the nature of this project — see `tests/fixtures/hostile_server.py` for
  the style of adversarial fixture we use internally)
- Any suggested fix, if you have one

We aim to acknowledge reports within 5 business days and to ship a fix or
mitigation before any public disclosure. Please give us a reasonable window
to respond before disclosing publicly.

## Scope

In scope:
- Bypasses of the output gate (a destructive/dangerous outbound tool call
  that should have been blocked but was forwarded to the real server)
- Bypasses of the input gate (injected content that should have been
  redacted but was relayed to the client unmodified)
- Any message shape or protocol framing that lets a hostile downstream MCP
  server evade gating, auditing, or crash/hang the proxy
- Vulnerabilities in the packaged default rule set that make it trivially
  bypassable (as opposed to signature quality/false-positive tuning, which
  is a regular issue, not a security report — see below)

Out of scope / please file a regular issue instead:
- False positives (benign content redacted because it happens to match a
  signature) — this is a tuning problem, file a normal issue with the
  offending signature and sample text
- Missing features or requests to gate additional message types beyond the
  documented v1 scope (see `docs/superpowers/specs/2026-09-26-mcp-protocol-proxy-design.md`
  section 3.2 for exactly what is and isn't covered)
- Vulnerabilities in a *wrapped* downstream MCP server itself — Aran gates
  what flows through it, but isn't responsible for the security of servers
  it wraps

## Design Context

Aran's threat model assumes the downstream MCP server it wraps may be
compromised or actively hostile, and is designed so that the proxy's
security guarantees never depend on a message shape, encoding, or framing
choice that a hostile server controls. If you find a case where they do,
that's exactly the class of bug we want reported here.
