from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    # NOT r"mv\s+.*+/dev/null": the possessive quantifier ".*+" consumes to
    # end-of-line and never backtracks, so "/dev/null" could never be found
    # and the pattern matched nothing at all (on 3.11+; on 3.10 it doesn't
    # even compile).
    r"mv\s+.*/dev/null",
]

INPUT_KEY = "input_gate_signatures"
OUTPUT_KEY = "output_gate_signatures"


@dataclass
class RuleLoadResult:
    """What load_rules_detailed found, so callers can tell a healthy config
    load apart from a silent fallback to the tiny built-in lists."""

    input_signatures: list[str]
    output_signatures: list[str]
    fallback_reasons: dict[str, str] = field(default_factory=dict)

    @property
    def used_fallback(self) -> bool:
        return bool(self.fallback_reasons)


def _is_signature_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _all_defaults(reason: str) -> RuleLoadResult:
    return RuleLoadResult(
        input_signatures=list(DEFAULT_INPUT_SIGNATURES),
        output_signatures=list(DEFAULT_OUTPUT_SIGNATURES),
        fallback_reasons={INPUT_KEY: reason, OUTPUT_KEY: reason},
    )


def load_rules_detailed(path: Path) -> RuleLoadResult:
    """Loads the input/output gate signatures from a YAML rules file, also
    reporting whether (and why) any of them fell back to the hardcoded
    built-in defaults. Never raises: the proxy must not crash or fail closed
    just because its config is bad."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return _all_defaults("file not found")
    except OSError as e:
        return _all_defaults(f"unreadable ({e.strerror or e})")
    except yaml.YAMLError:
        return _all_defaults("not parseable as YAML")

    if not isinstance(data, dict):
        return _all_defaults("top-level YAML value is not a mapping")

    result = RuleLoadResult(input_signatures=[], output_signatures=[])
    for key, default in ((INPUT_KEY, DEFAULT_INPUT_SIGNATURES), (OUTPUT_KEY, DEFAULT_OUTPUT_SIGNATURES)):
        value = data.get(key)
        if value is None or (isinstance(value, list) and not value):
            signatures = list(default)
            result.fallback_reasons[key] = f"{key} missing or empty"
        elif not _is_signature_list(value):
            # A bare string here would make list() yield one signature per
            # *character* (matching nearly every message); a non-string
            # element would reach re.search() as a non-pattern.
            signatures = list(default)
            result.fallback_reasons[key] = f"{key} is not a list of strings"
        else:
            signatures = list(value)
        if key == INPUT_KEY:
            result.input_signatures = signatures
        else:
            result.output_signatures = signatures
    return result


def load_rules(path: Path) -> tuple[list[str], list[str]]:
    """Loads (input_gate_signatures, output_gate_signatures) from a YAML
    rules file. Falls back to the hardcoded defaults if the file is
    missing, unreadable, unparseable, or has a malformed value for either
    key - the proxy must never crash or fail closed just because its config
    is bad. Use load_rules_detailed() when you also need to know whether a
    fallback happened."""
    result = load_rules_detailed(path)
    return result.input_signatures, result.output_signatures
