from __future__ import annotations

import sys
from pathlib import Path
from typing import BinaryIO

from mcp_shield.proxy import run_proxy
from mcp_shield.rules import load_rules

PACKAGE_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_RULES_PATH = PACKAGE_ROOT / "config" / "default-rules.yaml"
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


def main(
    argv: list[str] | None = None,
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        command = parse_args(argv)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    input_sigs, output_sigs = load_rules(DEFAULT_RULES_PATH)

    return run_proxy(
        command,
        input_signatures=input_sigs,
        output_signatures=output_sigs,
        audit_log_path=DEFAULT_AUDIT_LOG_PATH,
        client_in=stdin or sys.stdin.buffer,
        client_out=stdout or sys.stdout.buffer,
    )


if __name__ == "__main__":
    sys.exit(main())
