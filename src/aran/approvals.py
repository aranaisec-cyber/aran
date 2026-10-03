"""Human approval of an otherwise-blocked tool call, remembered for next time.

When the outbound gate blocks a call, Aran can park it here as a *pending*
approval with a short code. A human - and only a human - then approves or
declines it through a channel the agent has no tool for: the `aran approve`
terminal command (which refuses to run without an interactive TTY and asks
for confirmation) or a native desktop dialog Aran itself opens
(approval_dialog.py). The decision is stored keyed to the EXACT call (tool
name + arguments), so a retry of that same call passes - and a different
call, even one that trips the same signature, still has to be approved on
its own. Aran deliberately offers no MCP tool for approving: any channel an
agent can reach, a prompt injection can reach too.

Storage is one small file per entry (never one shared file) because two
different processes write here concurrently - the proxy creating a pending
entry, and the CLI or a dialog thread deciding it - and a read-modify-write
of a single JSON file would lose updates. Each file is created atomically
(write temp + os.replace), so there is nothing to lock.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from aran.audit import log_event

PENDING_TTL_SECONDS = 900
_PREVIEW_MAX_CHARS = 1500
# No 0/O/1/I - a code is read off a dialog or a chat message and typed back.
_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
_CODE_LENGTH = 6
CODE_PREFIX = "AR-"

KIND_SIGNATURE = "signature"
KIND_REPO_SCAN = "repo_scan"


class ApprovalError(Exception):
    """An unknown/expired code, or a store that could not be written."""


def call_key(tool_name: str, arguments: Any) -> str:
    """Identity of one tool call: tool name + canonical arguments. Hashed so
    the key is a safe filename and its size is independent of payload size."""
    try:
        canonical = json.dumps(arguments, sort_keys=True, default=str)
    except (TypeError, ValueError):
        canonical = repr(arguments)
    return hashlib.sha256(f"{tool_name}:{canonical}".encode("utf-8", errors="replace")).hexdigest()


# What a matched signature actually means for the person deciding. Keyed by
# the exact source string of each shipped output signature; a custom or
# unknown signature falls back to a generic line rather than guessing.
_SIGNATURE_RISKS = {
    r"rm\s+-[rfRF]+": "Deletes files or directories recursively without asking for confirmation.",
    r"chmod\s+777": "Makes files readable, writable and executable by every user on this machine.",
    r"mv\s+.*/dev/null": "Discards files by moving them to /dev/null - the data cannot be recovered.",
    r"dd\s+if=": "dd can overwrite disks or partitions with raw data, destroying what is on them.",
    r"mkfs(\.\w+)?\s+": "Formats a filesystem, erasing everything on the target device.",
    r">\s*/dev/sd[a-z]": "Writes directly to a disk device, which can destroy its contents.",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:": "A fork bomb: spawns processes until the machine stops responding.",
    r"curl\s+.*\|\s*(sh|bash)": "Downloads a script from the internet and runs it immediately, unreviewed.",
    r"wget\s+.*\|\s*(sh|bash)": "Downloads a script from the internet and runs it immediately, unreviewed.",
    r"curl\s+.*?\b(?:pastebin|webhook|exfil)\b": "Sends data to an external paste/webhook endpoint - a common way to leak secrets.",
}

_REPO_CATEGORY_RISKS = {
    "destructive_command": "contains a destructive command",
    "prompt_injection": "contains text that looks like a prompt injection",
    "secret": "contains what looks like a hardcoded credential",
    "supply_chain": "runs code fetched from the network during install/build",
}


def describe_risk(kind: str, matched_signature: str | None, detail: dict[str, Any] | None = None) -> str:
    if kind == KIND_REPO_SCAN:
        detail = detail or {}
        what = _REPO_CATEGORY_RISKS.get(str(detail.get("category")), "failed a content scan")
        return (
            f"The GitHub repo {detail.get('repo', '?')} {what} "
            f"(file {detail.get('file', '?')!r}). Cloning or running it could compromise this machine."
        )
    if matched_signature and matched_signature in _SIGNATURE_RISKS:
        return _SIGNATURE_RISKS[matched_signature]
    return "Matched a destructive-command signature - review the arguments carefully before approving."


@dataclass
class PendingApproval:
    code: str
    key: str
    tool_name: str
    kind: str
    matched_signature: str | None
    target_node: str | None
    risk: str
    preview: str
    args_chars: int
    created_at: float
    expires_at: float

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PendingApproval":
        return cls(**{f: data[f] for f in cls.__dataclass_fields__})  # type: ignore[attr-defined]


def _preview(arguments: Any) -> tuple[str, int]:
    try:
        text = json.dumps(arguments, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = repr(arguments)
    total = len(text)
    if total > _PREVIEW_MAX_CHARS:
        text = text[:_PREVIEW_MAX_CHARS] + f"\n... [{total - _PREVIEW_MAX_CHARS} more characters not shown]"
    return text, total


def format_review(pending: PendingApproval) -> str:
    """The text a human reads before deciding - shared by the terminal
    command and the desktop dialog so both show the same thing."""
    lines = [
        f"Tool:      {pending.tool_name}",
        f"Risk:      {pending.risk}",
    ]
    if pending.matched_signature:
        where = f" (in {pending.target_node})" if pending.target_node else ""
        lines.append(f"Matched:   {pending.matched_signature}{where}")
    lines.append("Arguments:")
    lines.extend(f"  {line}" for line in pending.preview.splitlines())
    if pending.args_chars > _PREVIEW_MAX_CHARS:
        lines.append(
            f"NOTE: the arguments are {pending.args_chars} characters long and only the "
            f"first {_PREVIEW_MAX_CHARS} are shown - approval covers the full call."
        )
    lines.append(f"Code:      {pending.code}")
    return "\n".join(lines)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def normalize_code(code: str) -> str:
    code = code.strip().upper()
    return code if code.startswith(CODE_PREFIX) else CODE_PREFIX + code


class ApprovalStore:
    def __init__(
        self,
        root: Path,
        *,
        audit_log_path: Path | None = None,
        pending_ttl: float = PENDING_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ):
        self.root = root
        self.audit_log_path = audit_log_path
        self.pending_ttl = pending_ttl
        self.clock = clock

    @property
    def _pending(self) -> Path:
        return self.root / "pending"

    @property
    def _approved(self) -> Path:
        return self.root / "approved"

    @property
    def _declined(self) -> Path:
        return self.root / "declined"

    def _audit(self, outcome: str, tool_name: str | None, signature: str | None, detail: dict[str, Any]) -> None:
        if self.audit_log_path is not None:
            log_event(
                self.audit_log_path,
                direction="approval",
                tool_name=tool_name,
                outcome=outcome,
                matched_signature=signature,
                detail=detail,
            )

    # -- lookups on the gate's hot path ------------------------------------

    def status(self, key: str) -> str | None:
        if (self._approved / f"{key}.json").exists():
            return "approved"
        if (self._declined / f"{key}.json").exists():
            return "declined"
        return None

    def consume_approval(self, key: str) -> bool:
        """True if this exact call is approved. A one-time approval is
        deleted by this check - unlink is the atomic claim, so two retries
        racing for one approval cannot both use it."""
        path = self._approved / f"{key}.json"
        data = _read_json(path)
        if data is None:
            return False
        if data.get("once"):
            try:
                path.unlink()
            except FileNotFoundError:
                return False
        return True

    # -- pending entries ------------------------------------------------------

    def _load_pending(self, path: Path) -> PendingApproval | None:
        data = _read_json(path)
        if data is None:
            return None
        try:
            pending = PendingApproval.from_dict(data)
        except (KeyError, TypeError):
            return None
        if pending.expires_at <= self.clock():
            try:
                path.unlink()
            except OSError:
                pass
            return None
        return pending

    def list_pending(self) -> list[PendingApproval]:
        if not self._pending.is_dir():
            return []
        found = []
        for path in sorted(self._pending.glob("*.json")):
            pending = self._load_pending(path)
            if pending is not None:
                found.append(pending)
        return sorted(found, key=lambda p: p.created_at)

    def get_pending(self, code: str) -> PendingApproval | None:
        return self._load_pending(self._pending / f"{normalize_code(code)}.json")

    def get_or_create_pending(
        self,
        key: str,
        *,
        tool_name: str,
        arguments: Any,
        kind: str,
        matched_signature: str | None,
        target_node: str | None,
        risk: str,
    ) -> tuple[PendingApproval, bool]:
        """One pending entry per distinct call: a blocked call the agent
        keeps retrying reuses its code instead of piling up (and re-prompting)."""
        for existing in self.list_pending():
            if existing.key == key:
                return existing, False
        preview, total = _preview(arguments)
        now = self.clock()
        for _ in range(20):
            code = CODE_PREFIX + "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))
            if not (self._pending / f"{code}.json").exists():
                break
        pending = PendingApproval(
            code=code,
            key=key,
            tool_name=tool_name,
            kind=kind,
            matched_signature=matched_signature,
            target_node=target_node,
            risk=risk,
            preview=preview,
            args_chars=total,
            created_at=now,
            expires_at=now + self.pending_ttl,
        )
        _write_json(self._pending / f"{code}.json", asdict(pending))
        return pending, True

    # -- human decisions -----------------------------------------------------

    def _take_pending(self, code: str) -> PendingApproval:
        pending = self.get_pending(code)
        if pending is None:
            raise ApprovalError(f"no pending approval {normalize_code(code)!r} (unknown, already decided, or expired)")
        return pending

    def approve(self, code: str, *, once: bool = False, via: str = "cli") -> PendingApproval:
        pending = self._take_pending(code)
        record = {
            "key": pending.key,
            "tool_name": pending.tool_name,
            "matched_signature": pending.matched_signature,
            "preview": pending.preview,
            "approved_at": self.clock(),
            "once": once,
            "via": via,
        }
        _write_json(self._approved / f"{pending.key}.json", record)
        for stale in (self._declined / f"{pending.key}.json", self._pending / f"{pending.code}.json"):
            try:
                stale.unlink()
            except OSError:
                pass
        self._audit(
            "approved", pending.tool_name, pending.matched_signature,
            {"code": pending.code, "via": via, "once": once, "key": pending.key[:12]},
        )
        return pending

    def decline(self, code: str, *, via: str = "cli") -> PendingApproval:
        pending = self._take_pending(code)
        record = {
            "key": pending.key,
            "tool_name": pending.tool_name,
            "matched_signature": pending.matched_signature,
            "preview": pending.preview,
            "declined_at": self.clock(),
            "via": via,
        }
        _write_json(self._declined / f"{pending.key}.json", record)
        for stale in (self._approved / f"{pending.key}.json", self._pending / f"{pending.code}.json"):
            try:
                stale.unlink()
            except OSError:
                pass
        self._audit(
            "declined", pending.tool_name, pending.matched_signature,
            {"code": pending.code, "via": via, "key": pending.key[:12]},
        )
        return pending

    # -- review / revoke ---------------------------------------------------------

    def list_decisions(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        def load(directory: Path) -> list[dict[str, Any]]:
            if not directory.is_dir():
                return []
            return [d for d in (_read_json(p) for p in sorted(directory.glob("*.json"))) if d]

        return load(self._approved), load(self._declined)

    def revoke(self, identifier: str) -> int:
        """Remove a remembered approval/decline by key prefix (>= 6 chars, as
        shown by `aran approvals`), or cancel a pending entry by code. Returns
        how many entries were removed."""
        identifier = identifier.strip()
        if len(identifier) < 6:
            raise ApprovalError("give at least 6 characters of the id shown by `aran approvals`")
        removed = 0
        lowered = identifier.lower()
        for directory in (self._approved, self._declined):
            if not directory.is_dir():
                continue
            for path in directory.glob("*.json"):
                if path.stem.startswith(lowered):
                    data = _read_json(path) or {}
                    try:
                        path.unlink()
                    except OSError:
                        continue
                    removed += 1
                    self._audit(
                        "revoked", data.get("tool_name"), data.get("matched_signature"),
                        {"key": path.stem[:12], "was": directory.name},
                    )
        pending = self._pending / f"{normalize_code(identifier)}.json"
        if pending.exists():
            try:
                pending.unlink()
                removed += 1
            except OSError:
                pass
        return removed


@dataclass
class ApprovalContext:
    """What the proxy needs to offer approvals: the store, plus an optional
    callback that tells a human a new pending approval exists (the desktop
    dialog). Bundled into one object so it threads through the gate as a
    single parameter."""

    store: ApprovalStore
    notify: Callable[[PendingApproval], object] | None = None
