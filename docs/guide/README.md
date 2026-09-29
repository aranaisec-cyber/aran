# Aran — Beginner's Guide

This folder is a step-by-step guide to Aran, written for someone who has
never used it (and may never have used MCP) before. Each file is a
self-contained lesson — read them in order the first time; afterwards, use
this page as an index to jump back to whichever one you need.

If you just want the fastest possible path to a working setup, the
[README.md](../../README.md) at the repo root is a shorter, denser version
of the same information. This guide is the slow, explained version —
useful the first time, or whenever "how does this actually work?" comes up.

## Reading order

1. **[What Is Aran?](01-what-is-aran.md)** — the problem it solves, the
   words it uses (MCP, stdio proxy, prompt injection), and how the pieces
   fit together. Start here even if you're impatient to run something —
   the rest of the guide assumes these concepts.
2. **[Installation](02-installation.md)** — getting Aran onto your machine,
   from a clean Python install to a working `aran` command, with every
   likely failure and its fix.
3. **[Quickstart](03-quickstart.md)** — your first Aran run, by hand, with
   no IDE involved: send it a message, watch it respond, see the audit log
   get its first line.
4. **[Wiring Aran into Your IDE](04-ide-integration.md)** — Claude Code,
   Cursor, and any other MCP-speaking tool: the one edit you make to your
   existing server config.
5. **[The Outbound Gate](05-outbound-gate.md)** — how Aran decides whether
   a tool call your agent is about to make is safe to send, worked through
   with real examples of an allowed call and a blocked one.
6. **[The Inbound Gate](06-inbound-gate.md)** — how Aran decides whether
   content coming back from a tool is safe for your agent to read, and the
   deliberate exceptions that keep the protocol itself working.
7. **[The Audit Log](07-audit-log.md)** — every field Aran writes to
   `~/.aran/audit.jsonl`, what each one means, and how to read it like a
   security log instead of a wall of JSON.
8. **[Modes & Configuration](08-modes-and-configuration.md)** — dry-run
   mode (`ARAN_MODE=audit`), the profiler (`ARAN_PROFILE=1`), and how to
   edit or refresh the signature rules Aran gates against.
9. **[Hands-On Walkthrough](09-hands-on-walkthrough.md)** — an extended,
   copy-pasteable session that fires every case in both gates (clean,
   blocked, evasion attempt, dry-run, protocol-field exemption, a hostile
   server trying to trick the proxy) and shows you the exact output and
   audit-log line each one produces. This is the "prove it to yourself"
   chapter.
10. **[Troubleshooting](10-troubleshooting.md)** — the specific error
    messages you might hit and what they mean, indexed so you can jump
    straight to yours.
11. **[FAQ](11-faq.md)** — short answers to the questions that don't need
    a whole chapter.

## What this guide is not

- It is not the project's internal design/architecture record — that lives
  in [`docs/superpowers/`](../superpowers/) and is written for contributors
  changing Aran's internals, not for people using it.
- It is not a release checklist — that's [`TESTING.md`](../../TESTING.md)
  at the repo root, aimed at maintainers verifying a build before it ships.
- It does not replace reading the code. Aran is a security tool; where this
  guide simplifies something, it links to the exact source file and line
  so you can go verify the claim yourself. Trusting a security tool you
  can't read the internals of is a worse position than not using one.
