"""Optional GitHub repo scan (ARAN_SCAN_GITHUB_REPOS=1).

When an outbound tool call references a public GitHub repo (see
gates.find_github_repo_reference), Aran can fetch that repo's contents and
scan every file against the same signature categories the rest of the proxy
already uses, plus two repo-specific ones (hardcoded secrets, supply-chain
install/build hooks), *before* the call that would clone/download it is
allowed through.

This is a deliberate, opt-in departure from the rest of Aran's "zero network
calls" posture: fetching a third party's repository content requires actually
reaching the network. See docs/guide/08-modes-and-configuration.md for the
user-facing explanation of that tradeoff and why it defaults to off.

Fetching goes through GitHub's codeload service (the same unauthenticated
download path `git clone` itself uses over HTTPS), not the api.github.com
REST API - this avoids that API's much stricter unauthenticated rate limit
for what is, per scan, exactly one HTTP request.
"""
from __future__ import annotations

import io
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from aran.gates import SignatureList, find_signature_match

# A repo fetched from the public internet is untrusted, adversarial-capable
# content - the same fail-closed-on-excess posture the rest of the proxy
# applies to JSON nesting/batch depth applies here to archive size, so a huge
# or deliberately bloated tarball can't exhaust memory or hang the scan.
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_FILES = 2000
DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_TOTAL_BYTES = 50_000_000

CODELOAD_URL = "https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"

# Skipped outright rather than decoded: these extensions cannot contain the
# shell/text-based payloads the signature categories below look for, and
# decoding them as text would either waste time or produce meaningless
# mojibake that happens to dodge or trip a pattern by accident.
_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".pdf",
    ".zip", ".gz", ".tar", ".7z", ".rar", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".so", ".dll", ".dylib", ".exe", ".bin",
    ".pyc", ".class", ".jar", ".wasm",
})


@dataclass
class RepoMatch:
    path: str
    category: str
    matched_signature: str


@dataclass
class RepoScanResult:
    owner: str
    repo: str
    ref: str
    matches: list[RepoMatch] = field(default_factory=list)
    files_scanned: int = 0
    # Set only when the fetch/scan itself could not be completed (network
    # error, timeout, repo not found, malformed archive, ...) - distinct from
    # "completed and found nothing". This is NOT a security finding; see
    # proxy.py's fail-open handling of it.
    error: str | None = None

    @property
    def blocked(self) -> bool:
        return self.error is None and bool(self.matches)


FetchTarballFn = Callable[[str, str, str], bytes]


def default_fetch_tarball(
    owner: str,
    repo: str,
    ref: str,
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    github_token: str | None = None,
) -> bytes:
    """Downloads a repo's gzipped tarball from GitHub's codeload service.
    `ref` may be a branch, tag, or commit SHA; the literal string "HEAD"
    resolves to the repo's default branch without a separate API lookup."""
    url = CODELOAD_URL.format(owner=owner, repo=repo, ref=ref)
    headers = {"User-Agent": "aran-repo-scan/1.0"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def scan_repo(
    owner: str,
    repo: str,
    *,
    ref: str = "HEAD",
    signatures_by_category: dict[str, SignatureList],
    fetch_tarball: FetchTarballFn = default_fetch_tarball,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> RepoScanResult:
    """Fetches `owner/repo`@`ref` and scans every text file's content against
    each signature category in `signatures_by_category` (category name ->
    signature list/compiled signatures, same shape gates.py already takes).
    Stops at the first matching category per file - one hit is enough to
    decide a file is unsafe, and stopping there keeps a large repo scan fast.

    A fetch or archive-level failure is reported via `result.error` and never
    raises - the caller (proxy.py) decides what a failed scan means for the
    call that triggered it; this function only ever reports what it found."""
    result = RepoScanResult(owner=owner, repo=repo, ref=ref)
    try:
        raw = fetch_tarball(owner, repo, ref)
    except (urllib.error.URLError, OSError, ValueError) as e:
        result.error = f"could not fetch {owner}/{repo}@{ref}: {e}"
        return result

    total_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                if result.files_scanned >= max_files or total_bytes >= max_total_bytes:
                    break
                name_lower = member.name.lower()
                if any(name_lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
                    continue
                if member.size > max_file_bytes:
                    continue
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                data = extracted.read()
                total_bytes += len(data)
                result.files_scanned += 1

                # codeload tarballs wrap everything in a single top-level
                # "<repo>-<ref>/" directory; strip it for a readable path.
                display_path = member.name.split("/", 1)[1] if "/" in member.name else member.name
                text = data.decode("utf-8", errors="ignore")

                for category, signatures in signatures_by_category.items():
                    matched = find_signature_match(text, signatures)
                    if matched:
                        result.matches.append(RepoMatch(display_path, category, matched))
                        break
    except tarfile.TarError as e:
        result.error = f"could not read archive for {owner}/{repo}@{ref}: {e}"

    return result
