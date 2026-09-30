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

# Used by the optional GitHub repo scan (ARAN_SCAN_GITHUB_REPOS=1, see
# repo_scan.py) to flag hardcoded credentials committed to a repo before it's
# cloned. Deliberately a small, well-known set of high-confidence formats
# (cloud provider / vendor key prefixes are distinctive enough that false
# positives are rare) rather than a generic "looks like a secret" heuristic,
# which would flag far too much ordinary-looking config and test fixture text.
DEFAULT_SECRET_SIGNATURES: list[str] = [
    r"AKIA[0-9A-Z]{16}",                                   # AWS access key ID
    r"ghp_[A-Za-z0-9]{36}",                                # GitHub PAT (classic)
    r"github_pat_[A-Za-z0-9_]{22,}",                       # GitHub PAT (fine-grained)
    r"xox[baprs]-[A-Za-z0-9-]{10,}",                       # Slack token
    r"AIza[0-9A-Za-z\-_]{35}",                             # Google API key
    r"sk-[A-Za-z0-9]{20,}",                                # OpenAI-style secret key
    r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",  # PEM private key block
]

# Used by the same optional repo scan to flag install/build tooling that
# fetches and executes remote code - a classic supply-chain attack vector
# distinct from both destructive-command signatures (which describe the
# command's *effect*) and prompt-injection signatures (which describe text
# aimed at an LLM, not a shell). Deliberately overlaps `curl|bash`-style
# patterns already in DEFAULT_OUTPUT_SIGNATURES: those exist to catch an
# *agent* being told to run one; these exist to catch one already sitting in
# a repo's own install/build scripts (setup.py, postinstall hooks, Makefiles,
# CI configs) before that repo is even cloned.
DEFAULT_SUPPLY_CHAIN_SIGNATURES: list[str] = [
    r"curl\s+.*\|\s*(sh|bash|python[0-9.]*)",
    r"wget\s+.*\|\s*(sh|bash|python[0-9.]*)",
    r"base64\s+(-d|--decode)\s*\|\s*(sh|bash)",
    r"eval\s*\(\s*(atob|base64)",
    r"iex\s*\(\s*New-Object\s+Net\.WebClient",             # PowerShell download cradle
    r"powershell(\.exe)?\s+-e(nc(odedcommand)?)?\s",       # encoded PowerShell payload
]

INPUT_KEY = "input_gate_signatures"
OUTPUT_KEY = "output_gate_signatures"
SECRET_KEY = "secret_signatures"
SUPPLY_CHAIN_KEY = "supply_chain_signatures"


# Maps each rules-file key to the RuleLoadResult attribute it fills, its
# built-in default, and whether its ABSENCE alone is worth a fallback warning.
# input/output are required: every rules file has always needed them, so a
# missing key is a real config problem worth surfacing (I4). secret/
# supply_chain are new, optional categories added for the GitHub repo scan -
# a rules file written before they existed is not misconfigured, so a file
# simply not having them yet is silent; only an actually malformed value for
# one of them (present, but not a list of strings) still reports a reason.
_RULE_SPECS: tuple[tuple[str, str, list[str], bool], ...] = (
    (INPUT_KEY, "input_signatures", DEFAULT_INPUT_SIGNATURES, True),
    (OUTPUT_KEY, "output_signatures", DEFAULT_OUTPUT_SIGNATURES, True),
    (SECRET_KEY, "secret_signatures", DEFAULT_SECRET_SIGNATURES, False),
    (SUPPLY_CHAIN_KEY, "supply_chain_signatures", DEFAULT_SUPPLY_CHAIN_SIGNATURES, False),
)


@dataclass
class RuleLoadResult:
    """What load_rules_detailed found, so callers can tell a healthy config
    load apart from a silent fallback to the tiny built-in lists."""

    input_signatures: list[str]
    output_signatures: list[str]
    secret_signatures: list[str] = field(default_factory=lambda: list(DEFAULT_SECRET_SIGNATURES))
    supply_chain_signatures: list[str] = field(default_factory=lambda: list(DEFAULT_SUPPLY_CHAIN_SIGNATURES))
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
        secret_signatures=list(DEFAULT_SECRET_SIGNATURES),
        supply_chain_signatures=list(DEFAULT_SUPPLY_CHAIN_SIGNATURES),
        fallback_reasons={key: reason for key, _, _, _ in _RULE_SPECS},
    )


def load_rules_detailed(path: Path) -> RuleLoadResult:
    """Loads the gate signatures from a YAML rules file, also reporting
    whether (and why) any of them fell back to the hardcoded built-in
    defaults. Never raises: the proxy must not crash or fail closed just
    because its config is bad."""
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

    result = RuleLoadResult(input_signatures=[], output_signatures=[], secret_signatures=[], supply_chain_signatures=[])
    for key, attr, default, required in _RULE_SPECS:
        value = data.get(key)
        is_absent = value is None or (isinstance(value, list) and not value)
        if is_absent:
            signatures = list(default)
            if required:
                result.fallback_reasons[key] = f"{key} missing or empty"
        elif not _is_signature_list(value):
            # A bare string here would make list() yield one signature per
            # *character* (matching nearly every message); a non-string
            # element would reach re.search() as a non-pattern.
            signatures = list(default)
            result.fallback_reasons[key] = f"{key} is not a list of strings"
        else:
            signatures = list(value)
        setattr(result, attr, signatures)
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
