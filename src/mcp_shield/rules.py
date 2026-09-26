from __future__ import annotations

from pathlib import Path

import yaml

DEFAULT_INPUT_SIGNATURES: list[str] = [
    "system override",
    "ignore prior instructions",
    "ignore previous instructions",
    "forget your rules",
]

DEFAULT_OUTPUT_SIGNATURES: list[str] = [
    r"rm\s+-[rfRF]+",
    r"chmod\s+777",
    r"mv\s+.*+/dev/null",
]


def load_rules(path: Path) -> tuple[list[str], list[str]]:
    """Loads (input_gate_signatures, output_gate_signatures) from a YAML
    rules file. Falls back to the hardcoded defaults if the file is
    missing, unreadable, or fails to parse - the proxy must never crash or
    fail closed just because its config is bad."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return list(DEFAULT_INPUT_SIGNATURES), list(DEFAULT_OUTPUT_SIGNATURES)

    # Ensure data is a dict; if not, treat as invalid and return defaults
    if not isinstance(data, dict):
        return list(DEFAULT_INPUT_SIGNATURES), list(DEFAULT_OUTPUT_SIGNATURES)

    input_sigs = data.get("input_gate_signatures") or DEFAULT_INPUT_SIGNATURES
    output_sigs = data.get("output_gate_signatures") or DEFAULT_OUTPUT_SIGNATURES
    return list(input_sigs), list(output_sigs)
