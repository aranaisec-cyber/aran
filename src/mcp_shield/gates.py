from __future__ import annotations

import json
import re


def find_signature_match(text: str, signatures: list[str]) -> str | None:
    """Returns the first signature whose regex matches text (case-insensitive
    substring search), or None if none match. A signature that isn't valid
    regex is skipped rather than raising, so one bad config entry can't take
    the whole gate down."""
    lowered = text.lower()
    for pattern in signatures:
        try:
            if re.search(pattern, lowered):
                return pattern
        except re.error:
            continue
    return None


def check_output(tool_name: str, arguments: dict, signatures: list[str]) -> str | None:
    """Checks an outbound tools/call (tool name + arguments) against the
    output gate signatures. Returns the matched signature, or None if clean."""
    combined = f"{tool_name} {json.dumps(arguments, sort_keys=True)}"
    return find_signature_match(combined, signatures)


def check_input(text: str, signatures: list[str]) -> str | None:
    """Checks inbound tool-result text against the input gate signatures.
    Returns the matched signature, or None if clean."""
    return find_signature_match(text, signatures)
