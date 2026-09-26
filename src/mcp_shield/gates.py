from __future__ import annotations

import re
from typing import Any

# Depth cap for walking decoded JSON argument structures. Real tool-call
# arguments are shallow; anything deeper is either a bug or a hostile payload
# trying to blow the recursion limit inside the gate.
_MAX_WALK_DEPTH = 200


def find_signature_match(text: str, signatures: list[str]) -> str | None:
    """Returns the first signature whose regex matches text (case-insensitive
    substring search), or None if none match. A signature that isn't valid
    regex - or isn't a string at all - is skipped rather than raising, so one
    bad config entry can't take the whole gate down."""
    for pattern in signatures:
        try:
            # Matching is case-insensitive via re.IGNORECASE against the
            # ORIGINAL text. Lowercasing the haystack instead would silently
            # break any signature containing an uppercase literal (e.g.
            # "AKIA[0-9A-Z]{16}"), which is exactly the class of signature
            # most likely to be added next.
            if re.search(pattern, text, re.IGNORECASE):
                return pattern
        except (re.error, TypeError):
            # TypeError covers a non-string signature slipping through
            # validation (e.g. an unquoted number in the YAML config); it is
            # NOT a subclass of re.error, so it has to be caught explicitly.
            continue
    return None


def _collect_strings(value: Any, out: list[str], depth: int = 0) -> None:
    """Recursively collects the decoded string content of value into out.

    Dict keys are collected alongside values so coverage matches the old
    json.dumps()-based text, and scalars are stringified so a numeric
    argument can still be matched."""
    if depth > _MAX_WALK_DEPTH:
        raise ValueError("argument structure nested too deeply to inspect")
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for key in sorted(value, key=lambda k: str(k)):
            out.append(str(key))
            _collect_strings(value[key], out, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _collect_strings(item, out, depth + 1)
    elif value is None:
        return
    else:
        out.append(str(value))


def check_output(tool_name: str, arguments: Any, signatures: list[str]) -> str | None:
    """Checks an outbound tools/call (tool name + arguments) against the
    output gate signatures. Returns the matched signature, or None if clean.

    The haystack is built from the *decoded* argument values, not from
    json.dumps(arguments): JSON-encoding turns a literal tab into the two
    characters '\\' + 't', which no longer matches \\s, so an attacker could
    evade nearly every shipped signature just by using a tab instead of a
    space."""
    parts: list[str] = [str(tool_name)]
    _collect_strings(arguments, parts)
    return find_signature_match("\n".join(parts), signatures)


def check_input(text: str, signatures: list[str]) -> str | None:
    """Checks inbound tool-result text against the input gate signatures.
    Returns the matched signature, or None if clean."""
    return find_signature_match(text, signatures)
