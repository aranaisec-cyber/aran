# 5. The Outbound Gate

The outbound gate inspects every `tools/call` request **before** it's
forwarded to the real MCP server — the direction your agent's decisions
flow out toward your machine's tools. Its job is narrow and specific:
catch known-destructive commands and stop them before they run anywhere.

## What it checks

For every outbound tool call, Aran looks at the tool's **name** and its
**arguments** (recursively — arguments can be nested objects or lists) and
checks the combined text against a list of **output signatures**: regular
expressions describing destructive command patterns. The built-in
defaults, before any custom rules are loaded
(from [`src/aran/rules.py`](../../src/aran/rules.py)):

```python
r"rm\s+-[rfRF]+"      # rm -rf, rm -Rf, rm -RF, ...
r"chmod\s+777"        # chmod 777 (world-writable permissions)
r"mv\s+.*/dev/null"   # mv <anything> /dev/null (silent data destruction)
```

The real, shipped rule set is much larger — see
[8. Modes & Configuration](08-modes-and-configuration.md) for where it
lives and how to extend it.

A key detail: matching happens against the **decoded** text, not the raw
JSON bytes. `rm -rf /` and `rm\t-rf /` (a literal tab instead of a space)
look different once JSON-encoded (`\t` is an escape sequence in the raw
bytes), but decode to text that both match `rm\s+-[rfRF]+` (`\s` means
"any whitespace"). Aran checks the decoded value specifically so this kind
of whitespace substitution can't be used to slip a destructive command
past the gate.

## What happens on a match

If a call matches, Aran:

1. **Never forwards the call** to the real server — the server process
   literally never receives those bytes.
2. **Synthesizes a JSON-RPC error response** and sends that back to your
   agent instead, with the same `id` the original call used (so your
   agent's request/response bookkeeping stays consistent).
3. **Writes one line to the audit log** with `"outcome": "blocked"`.

## Worked example: a clean call

```bash
printf '%s\n' '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}}' \
  | python -m aran.cli -- python tests/fixtures/fake_server.py
```

```json
{"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ran list_files"}]}}
```

Nothing in the tool name or arguments matches any signature, so the call
passes through to the practice server untouched, and its real reply comes
straight back.

## Worked example: a blocked call

```bash
printf '%s\n' '{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "rm -rf /", "cwd": "/tmp"}}}' \
  | python -m aran.cli -- python tests/fixtures/fake_server.py
```

```json
{"jsonrpc": "2.0", "id": 2, "error": {"code": -32001, "message": "[Aran] blocked: outbound call matched signature 'rm\\s+-[rfRF]+'", "data": {"violation": "destructive command signature matched", "matched_signature": "rm\\s+-[rfRF]+", "target_node": "arguments.command"}}}
```

Note that the practice server's usual `"ran run_command"` text never
appears anywhere — proof the call never reached it. Breaking down the
error object field by field:

| Field | Meaning |
|---|---|
| `error.code` | `-32001` specifically means *a destructive signature matched* — the gate worked exactly as designed. (A bare `-32000` with no `data` field instead means something different — see below.) |
| `error.message` | Human-readable summary, including which signature (regex pattern) matched. |
| `error.data.violation` | A short, stable label for what kind of problem this is (`"destructive command signature matched"`). |
| `error.data.matched_signature` | The exact regex pattern that matched, so you can look it up in your rules file if you need to adjust it. |
| `error.data.target_node` | Best-effort indication of *where* in the call the match was found — `"tool_name"`, `"arguments.<key>"` for a specific top-level argument, or a bare `"arguments"` fallback when the arguments aren't a simple object. This is diagnostic context only; it never influences whether the call is blocked. |

## Worked example: a whitespace-evasion attempt

```bash
printf '%s\n' '{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "rm\t-rf /"}}}' \
  | python -m aran.cli -- python tests/fixtures/fake_server.py
```

```json
{"jsonrpc": "2.0", "id": 3, "error": {"code": -32001, "message": "[Aran] blocked: outbound call matched signature 'rm\\s+-[rfRF]+'", ...}}
```

Still blocked, for the reason explained above: a shell treats a tab and a
space identically between `rm` and `-rf`, and Aran's matching does too.

## `-32000` vs `-32001` — two different kinds of "not forwarded"

Both codes mean the call didn't reach the server, but for different
reasons, and the distinction matters when you're debugging:

- **`-32001`, with a `data` field** — a real signature match. The gate did
  exactly its job. See the worked example above.
- **`-32000`, with no `data` field** — Aran itself couldn't safely inspect
  the message at all (malformed JSON, a shape it can't safely walk, an
  internal failure). This is the **fail-closed** path: when Aran can't
  tell whether something is safe, it refuses to guess and blocks it
  anyway, but this is a different situation from a genuine signature
  match, hence the different code and the absence of match details.

If you see `-32000` regularly, it's worth investigating what shape of
message is triggering it — it may point at a real compatibility issue
between Aran and the specific server you're wrapping. `-32001` appearing
is Aran working as intended.

## What the outbound gate does *not* do

- It doesn't run or simulate the command to see what it would do — it's a
  pattern match against text, which is fast and has no side effects, but
  also means an attack phrased in a way no signature covers can get
  through. This is why the rule list matters and why you can extend it
  (see [8. Modes & Configuration](08-modes-and-configuration.md)).
- It doesn't touch anything about the tool *result* — that's a separate
  check, covered next.

## Blocked, but you actually want it?

A block doesn't have to be the end. Aran can park the blocked call under an approval code and let **you** approve or decline that exact call from a desktop dialog or `aran approve CODE` - the agent can't approve for itself. See [12. Human Approval](12-approvals.md).

## Next

[6. The Inbound Gate](06-inbound-gate.md) — the other half of the
protection, checking what comes back from the server instead of what goes
out to it.
