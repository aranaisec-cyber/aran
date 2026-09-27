from __future__ import annotations

import re
from typing import Any, NamedTuple, Sequence

# Depth cap for walking decoded JSON argument structures. Real tool-call
# arguments are shallow; anything deeper is either a bug or a hostile payload
# trying to blow the recursion limit inside the gate.
_MAX_WALK_DEPTH = 200


class CompiledSignature(NamedTuple):
    """One signature plus its compiled pattern.

    The gate now runs against every string leaf of every inbound response, so
    the shipped 209-signature set was being re-resolved through re.search()'s
    module-level wrapper hundreds of times per leaf - seconds of CPU for a large
    tools/list payload on the single-threaded inbound relay (N3). Compiling once
    at startup and calling Pattern.search() directly removes that overhead.

    `source` is the original pattern string, so the audit log and the gates'
    return values keep naming the rule an operator wrote."""

    source: str
    pattern: re.Pattern[str]


# Either form is accepted everywhere a signature list is taken: raw strings
# (tests, ad-hoc callers) or precompiled entries (the proxy's hot path).
SignatureList = Sequence[Any]


def compile_signatures(signatures: SignatureList) -> list[CompiledSignature]:
    """Compiles a signature list once, for repeated matching.

    Entries that are not usable as a pattern are dropped here rather than
    skipped on every call - same net effect as find_signature_match's per-call
    guard, but paid once. Already-compiled entries pass through, so calling this
    twice is harmless."""
    compiled: list[CompiledSignature] = []
    for pattern in signatures:
        if isinstance(pattern, CompiledSignature):
            compiled.append(pattern)
            continue
        try:
            # Matching is case-insensitive via re.IGNORECASE against the
            # ORIGINAL text. Lowercasing the haystack instead would silently
            # break any signature containing an uppercase literal (e.g.
            # "AKIA[0-9A-Z]{16}"), which is exactly the class of signature
            # most likely to be added next.
            compiled.append(CompiledSignature(pattern, re.compile(pattern, re.IGNORECASE)))
        except (re.error, TypeError):
            # TypeError covers a non-string signature slipping through
            # validation (e.g. an unquoted number in the YAML config); it is
            # NOT a subclass of re.error, so it has to be caught explicitly.
            continue
    return compiled


def find_signature_match(text: str, signatures: SignatureList) -> str | None:
    """Returns the first signature whose regex matches text (case-insensitive
    substring search), or None if none match. A signature that isn't valid
    regex - or isn't a string at all - is skipped rather than raising, so one
    bad config entry can't take the whole gate down.

    Accepts precompiled CompiledSignature entries (see compile_signatures) as
    well as raw pattern strings; the returned value is the pattern string either
    way."""
    for entry in signatures:
        if isinstance(entry, CompiledSignature):
            if entry.pattern.search(text):
                return entry.source
            continue
        try:
            if re.search(entry, text, re.IGNORECASE):
                return entry
        except (re.error, TypeError):
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


def check_output(tool_name: str, arguments: Any, signatures: SignatureList) -> str | None:
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


def check_input(text: str, signatures: SignatureList) -> str | None:
    """Checks inbound tool-result text against the input gate signatures.
    Returns the matched signature, or None if clean."""
    return find_signature_match(text, signatures)
