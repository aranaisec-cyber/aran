from __future__ import annotations

import importlib.resources
import os
import shutil
import sys
from pathlib import Path
from typing import BinaryIO

from aran.proxy import run_proxy
from aran.rules import INPUT_KEY, OUTPUT_KEY, load_rules_detailed

RULES_FILE_NAME = "default-rules.yaml"


def default_rules_path() -> Path:
    """Locates the shipped rules file *inside the installed package*.

    A Path(__file__).parent.parent.parent walk only finds a repo-root config/
    directory under `pip install -e`; for a real wheel install it points at
    site-packages' parent, the file isn't there, and the proxy silently drops
    to the handful of hardcoded built-in signatures."""
    return Path(str(importlib.resources.files("aran").joinpath(RULES_FILE_NAME)))


DEFAULT_RULES_PATH = default_rules_path()
DEFAULT_AUDIT_LOG_PATH = Path.home() / ".aran" / "audit.jsonl"

USAGE = "usage: aran -- <command to launch the real MCP server> [args...]"


def parse_args(argv: list[str]) -> list[str]:
    """Splits `aran -- <command...>` and returns the downstream command.
    Raises ValueError with a usage message if `--` is missing or the
    command after it is empty."""
    if "--" not in argv:
        raise ValueError(USAGE)
    separator_index = argv.index("--")
    command = argv[separator_index + 1:]
    if not command:
        raise ValueError(USAGE)
    return command


def resolve_command(command: list[str]) -> list[str]:
    """Resolves the executable via shutil.which so PATHEXT-based launchers
    work. On Windows, CreateProcess (behind subprocess.Popen) resolves only
    .exe, so `aran -- npx ...` - the documented quickstart - would raise
    WinError 2 even though npx.CMD is on PATH. If which() finds nothing the
    original string is kept, so a genuinely missing command still produces the
    normal launch error."""
    if not command:
        return command
    resolved = shutil.which(command[0])
    if resolved is None:
        return command
    return [resolved, *command[1:]]


def audit_only_enabled(env: dict[str, str]) -> bool:
    """ARAN_MODE=audit disables blocking/redaction entirely - every match is
    logged as "would_block" but always forwarded unmodified. Any other value
    (including unset) is the normal, enforcing mode; this is opt-in, not
    opt-out, so a typo in the env var fails safe rather than silently
    disabling protection."""
    return env.get("ARAN_MODE", "").strip().lower() == "audit"


def profile_enabled(env: dict[str, str]) -> bool:
    """ARAN_PROFILE=1 (or any other non-empty, non-"0"/"false" value) prints a
    timing/signature-count line to stderr for every gated message."""
    value = env.get("ARAN_PROFILE", "").strip().lower()
    return value not in ("", "0", "false")


def scan_github_repos_enabled(env: dict[str, str]) -> bool:
    """ARAN_SCAN_GITHUB_REPOS=1 (or any other non-empty, non-"0"/"false"
    value) enables the optional GitHub repo scan: an outbound call
    referencing a public GitHub repo has that repo fetched and scanned
    before the call is forwarded (see repo_scan.py). Off by default because,
    unlike every other check in this proxy, it makes real network requests -
    opt-in, not opt-out, so upgrading Aran never silently starts reaching
    the network for anyone who hasn't asked for this."""
    value = env.get("ARAN_SCAN_GITHUB_REPOS", "").strip().lower()
    return value not in ("", "0", "false")


def _warn_about_rules_fallback(path: Path, reasons: dict[str, str], input_count: int, output_count: int) -> None:
    unique_reasons = list(dict.fromkeys(reasons.values()))
    counts = []
    if INPUT_KEY in reasons:
        counts.append(f"{input_count} built-in input")
    if OUTPUT_KEY in reasons:
        counts.append(f"{output_count} built-in output")
    print(
        f"[Aran] warning: could not load {path} ({'; '.join(unique_reasons)}), "
        f"using {' and '.join(counts)} signatures instead",
        file=sys.stderr,
    )


def main(
    argv: list[str] | None = None,
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    env: dict[str, str] | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    env = dict(os.environ) if env is None else env
    try:
        command = parse_args(argv)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    rules = load_rules_detailed(DEFAULT_RULES_PATH)
    if rules.used_fallback:
        # Falling back keeps the proxy running, but doing it silently makes a
        # missing/mistyped/unpackaged rules file indistinguishable from a
        # healthy run with hundreds of signatures loaded.
        _warn_about_rules_fallback(
            DEFAULT_RULES_PATH,
            rules.fallback_reasons,
            len(rules.input_signatures),
            len(rules.output_signatures),
        )

    audit_only = audit_only_enabled(env)
    if audit_only:
        # Printed unconditionally, every run, specifically so a developer who
        # left ARAN_MODE=audit set in their shell profile notices it - audit
        # mode looks identical to normal operation except that nothing is
        # ever actually blocked.
        print(
            "[Aran] audit mode (ARAN_MODE=audit): blocking and redaction are "
            "disabled, matches are logged only",
            file=sys.stderr,
        )

    scan_github_repos = scan_github_repos_enabled(env)
    if scan_github_repos:
        # Same reasoning as the audit-mode notice above, but this one matters
        # more: it's the only toggle in this file that makes Aran itself
        # reach the network, so a developer should never be surprised by it.
        print(
            "[Aran] GitHub repo scan enabled (ARAN_SCAN_GITHUB_REPOS=1): an "
            "outbound call referencing a public GitHub repo will have that "
            "repo fetched and scanned before being forwarded - this makes "
            "network requests to GitHub",
            file=sys.stderr,
        )

    try:
        return run_proxy(
            resolve_command(command),
            input_signatures=rules.input_signatures,
            output_signatures=rules.output_signatures,
            audit_log_path=DEFAULT_AUDIT_LOG_PATH,
            client_in=stdin or sys.stdin.buffer,
            client_out=stdout or sys.stdout.buffer,
            audit_only=audit_only,
            profile=profile_enabled(env),
            scan_github_repos=scan_github_repos,
            secret_signatures=rules.secret_signatures,
            supply_chain_signatures=rules.supply_chain_signatures,
        )
    except OSError as e:
        # Popen failures (command not found, not executable, ...) must surface
        # as a clean one-line [Aran] message, not a raw traceback.
        print(f"[Aran] failed to launch downstream server: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
