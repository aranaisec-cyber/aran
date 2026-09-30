import io
import json
import tarfile
from pathlib import Path

from aran.proxy import run_proxy


def _make_tarball(files: dict[str, bytes], top_dir: str = "demo-repo-main") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in files.items():
            info = tarfile.TarInfo(name=f"{top_dir}/{path}")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _fetcher(tarball_bytes: bytes):
    def fetch(owner: str, repo: str, ref: str) -> bytes:
        return tarball_bytes
    return fetch


def _requests_to_bytes(messages: list[dict]) -> io.BytesIO:
    data = "".join(json.dumps(m) + "\n" for m in messages).encode("utf-8")
    return io.BytesIO(data)


def _parse_responses(buf: io.BytesIO) -> list[dict]:
    text = buf.getvalue().decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


CLONE_CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "run_command", "arguments": {"command": "git clone https://github.com/octocat/demo-repo /tmp/x"}},
}


def test_repo_scan_disabled_by_default_forwards_without_fetching(tmp_path: Path, fake_server_command: list[str]):
    """scan_github_repos=False (the default) must not call fetch_tarball at
    all - not even to decide there's nothing to do - so a plain upgrade to a
    version of Aran with this feature changes nothing for anyone who hasn't
    opted in."""
    calls = []

    def spy_fetch(owner, repo, ref):
        calls.append((owner, repo, ref))
        raise AssertionError("must not be called when scan_github_repos is False")

    client_out = io.BytesIO()
    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=tmp_path / "audit.jsonl",
        client_in=_requests_to_bytes([CLONE_CALL]),
        client_out=client_out,
        scan_github_repos=False,
        fetch_tarball=spy_fetch,
    )

    assert code == 0
    assert calls == []
    responses = _parse_responses(client_out)
    assert "error" not in responses[0]


def test_repo_scan_blocks_a_call_referencing_a_repo_with_a_destructive_script(
    tmp_path: Path, fake_server_command: list[str]
):
    audit_path = tmp_path / "audit.jsonl"
    tarball = _make_tarball({"install.sh": b"rm -rf /\n"})
    client_out = io.BytesIO()

    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=audit_path,
        client_in=_requests_to_bytes([CLONE_CALL]),
        client_out=client_out,
        scan_github_repos=True,
        fetch_tarball=_fetcher(tarball),
    )

    assert code == 0
    responses = _parse_responses(client_out)
    assert responses[0]["error"]["code"] == -32002
    assert responses[0]["error"]["data"]["repo"] == "octocat/demo-repo"
    assert responses[0]["error"]["data"]["file"] == "install.sh"
    assert responses[0]["error"]["data"]["category"] == "destructive_command"
    # never reached the real server
    assert "ran run_command" not in json.dumps(responses)

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    repo_events = [e for e in events if e.get("detail", {}).get("repo") == "octocat/demo-repo"]
    assert len(repo_events) == 1
    assert repo_events[0]["outcome"] == "blocked"


def test_repo_scan_allows_a_call_referencing_a_clean_repo(tmp_path: Path, fake_server_command: list[str]):
    audit_path = tmp_path / "audit.jsonl"
    tarball = _make_tarball({"README.md": b"# demo-repo\nJust a normal project.\n"})
    client_out = io.BytesIO()

    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=audit_path,
        client_in=_requests_to_bytes([CLONE_CALL]),
        client_out=client_out,
        scan_github_repos=True,
        fetch_tarball=_fetcher(tarball),
    )

    assert code == 0
    responses = _parse_responses(client_out)
    assert "error" not in responses[0]
    assert responses[0]["result"]["content"][0]["text"] == "ran run_command"

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    repo_events = [e for e in events if e.get("detail", {}).get("repo") == "octocat/demo-repo"]
    assert repo_events[0]["outcome"] == "allowed"


def test_repo_scan_audit_only_mode_forwards_instead_of_blocking(tmp_path: Path, fake_server_command: list[str]):
    audit_path = tmp_path / "audit.jsonl"
    tarball = _make_tarball({"install.sh": b"rm -rf /\n"})
    client_out = io.BytesIO()

    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[r"rm\s+-[rfRF]+"],
        audit_log_path=audit_path,
        client_in=_requests_to_bytes([CLONE_CALL]),
        client_out=client_out,
        scan_github_repos=True,
        fetch_tarball=_fetcher(tarball),
        audit_only=True,
    )

    assert code == 0
    responses = _parse_responses(client_out)
    assert "error" not in responses[0]
    assert responses[0]["result"]["content"][0]["text"] == "ran run_command"

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    repo_events = [e for e in events if e.get("detail", {}).get("repo") == "octocat/demo-repo"]
    assert repo_events[0]["outcome"] == "would_block"


def test_repo_scan_fails_open_when_the_fetch_errors(tmp_path: Path, fake_server_command: list[str], capsys):
    """A network error, timeout, or rate limit is NOT a security finding -
    the call must still be forwarded (this is opt-in and best-effort, unlike
    the fail-closed policy for messages Aran itself cannot parse)."""
    audit_path = tmp_path / "audit.jsonl"

    def failing_fetch(owner, repo, ref):
        raise OSError("network unreachable")

    client_out = io.BytesIO()
    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=audit_path,
        client_in=_requests_to_bytes([CLONE_CALL]),
        client_out=client_out,
        scan_github_repos=True,
        fetch_tarball=failing_fetch,
    )

    assert code == 0
    responses = _parse_responses(client_out)
    assert "error" not in responses[0]
    assert responses[0]["result"]["content"][0]["text"] == "ran run_command"

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    repo_events = [e for e in events if e.get("detail", {}).get("repo") == "octocat/demo-repo"]
    assert repo_events[0]["outcome"] == "error"
    assert "network unreachable" in repo_events[0]["detail"]["reason"]

    err = capsys.readouterr().err
    assert "did not complete" in err


def test_repo_scan_does_nothing_for_a_call_with_no_github_reference(tmp_path: Path, fake_server_command: list[str]):
    audit_path = tmp_path / "audit.jsonl"
    calls = []

    def spy_fetch(owner, repo, ref):
        calls.append((owner, repo, ref))
        return _make_tarball({"README.md": b"clean"})

    client_out = io.BytesIO()
    code = run_proxy(
        fake_server_command,
        input_signatures=[], output_signatures=[],
        audit_log_path=audit_path,
        client_in=_requests_to_bytes([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}},
        ]),
        client_out=client_out,
        scan_github_repos=True,
        fetch_tarball=spy_fetch,
    )

    assert code == 0
    assert calls == []
    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert not any("detail" in e for e in events)
