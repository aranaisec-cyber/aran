"""The developer's personal, local overrides - ~/.aran/allowlist.yaml.

Distinct from src/aran/default-rules.yaml in a load-bearing way: the rules
file is shared, shipped, and gets overwritten wholesale by
scripts/sync_threat_intel.py. A developer's own "this specific signature is
a false positive for me" or "I trust this repo, skip the scan" decisions
would be silently wiped out by the next sync if they lived there instead.
This file is never touched by anything but the developer's own editor -
Aran only ever reads it.

Its absence is the normal case, not a degraded one (unlike a missing rules
file): most developers will never create this file, and nothing here warns
about that - there is nothing to warn about.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

ALLOWED_SIGNATURES_KEY = "allowed_signatures"
TRUSTED_REPOS_KEY = "trusted_repos"


@dataclass
class Allowlist:
    signatures: set[str] = field(default_factory=set)
    trusted_repos: set[str] = field(default_factory=set)


def load_allowlist(path: Path) -> Allowlist:
    """Never raises and never falls back to anything - a missing, empty, or
    malformed allowlist file just means no overrides are active, not an
    error condition. Malformed individual keys (present but not a list) are
    treated the same way: ignored, not warned about - this file's failure
    mode is "your override didn't take effect," never "the gate is
    disabled," so silence here can't weaken anything."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return Allowlist()
    if not isinstance(data, dict):
        return Allowlist()

    signatures = data.get(ALLOWED_SIGNATURES_KEY)
    trusted_repos = data.get(TRUSTED_REPOS_KEY)
    return Allowlist(
        signatures={s for s in signatures if isinstance(s, str)} if isinstance(signatures, list) else set(),
        trusted_repos={r for r in trusted_repos if isinstance(r, str)} if isinstance(trusted_repos, list) else set(),
    )


def filter_signatures(signatures, allowed: set[str]) -> list[str]:
    """Drops any signature whose SOURCE STRING is in `allowed`. Matching is
    exact-string, deliberately not fuzzy: `allowed` is meant to be populated
    by copy-pasting a `matched_signature` value straight out of the audit
    log, so exact-match is what makes that workflow actually work - a fuzzy
    match could silently disable more than the developer meant to."""
    if not allowed:
        return list(signatures)
    return [s for s in signatures if s not in allowed]


def is_trusted_repo(owner: str, repo: str, trusted_repos: set[str]) -> bool:
    """`owner/repo` (exact, case-insensitive) or `owner/*` (every repo under
    that owner) in the allowlist skips the GitHub content scan for that repo
    entirely - no fetch, no network call, not just "scanned and allowed"."""
    if not trusted_repos:
        return False
    normalized = {t.lower() for t in trusted_repos}
    owner_lower = owner.lower()
    if f"{owner_lower}/{repo.lower()}" in normalized:
        return True
    return f"{owner_lower}/*" in normalized
