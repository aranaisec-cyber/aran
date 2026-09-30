import io
import json
import shutil
import sys
from pathlib import Path

import pytest

from aran import cli
from aran.rules import DEFAULT_INPUT_SIGNATURES


def test_parse_args_splits_on_separator():
    assert cli.parse_args(["--", "npx", "server", "--flag"]) == ["npx", "server", "--flag"]


def test_parse_args_raises_when_separator_missing():
    with pytest.raises(ValueError):
        cli.parse_args(["npx", "server"])


def test_parse_args_raises_when_command_empty():
    with pytest.raises(ValueError):
        cli.parse_args(["--"])


def test_main_returns_usage_error_when_separator_missing(capsys):
    code = cli.main(["npx", "server"], stdin=io.BytesIO(b""), stdout=io.BytesIO())
    assert code == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_main_end_to_end_blocks_destructive_command(tmp_path, monkeypatch, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}},
    }
    stdin = io.BytesIO((json.dumps(request) + "\n").encode("utf-8"))
    stdout = io.BytesIO()

    # env={} (not the real process environment): a developer who happens to
    # have ARAN_MODE=audit set in their own shell must not silently flip this
    # test's expected outcome.
    cli.main(["--", *fake_server_command], stdin=stdin, stdout=stdout, env={})

    response = json.loads(stdout.getvalue().decode("utf-8").strip())
    assert response["error"]["code"] == -32001


# --- C3: PATHEXT-style command resolution and clean launch failures ---------

def test_resolve_command_resolves_a_plain_executable_name_via_which():
    name = Path(sys.executable).name
    expected = shutil.which(name)

    resolved = cli.resolve_command([name, "-c", "pass"])

    if expected is None:  # pragma: no cover - depends on PATH
        assert resolved == [name, "-c", "pass"]
    else:
        assert resolved == [expected, "-c", "pass"]
        assert Path(resolved[0]).is_absolute()
        assert resolved[0] != name  # the bare name was actually rewritten


def test_resolve_command_keeps_an_unresolvable_name_unchanged():
    assert cli.resolve_command(["aran-no-such-command-xyz", "-x"]) == [
        "aran-no-such-command-xyz",
        "-x",
    ]


def test_resolve_command_handles_an_empty_command():
    assert cli.resolve_command([]) == []


def test_main_end_to_end_works_with_a_bare_executable_name(tmp_path, monkeypatch, fake_server_command):
    """The documented `aran -- npx ...` form passes a bare launcher name; make
    sure a bare name resolved through which() still runs end to end."""
    bare_name = Path(sys.executable).name
    if shutil.which(bare_name) is None:  # pragma: no cover - depends on PATH
        pytest.skip(f"{bare_name} is not on PATH")
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "list_files", "arguments": {}},
    }
    stdin = io.BytesIO((json.dumps(request) + "\n").encode("utf-8"))
    stdout = io.BytesIO()

    code = cli.main(["--", bare_name, fake_server_command[1]], stdin=stdin, stdout=stdout)

    assert code == 0
    response = json.loads(stdout.getvalue().decode("utf-8").strip())
    assert response["result"]["content"][0]["text"] == "ran list_files"


def test_main_reports_a_launch_failure_cleanly_instead_of_a_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")

    code = cli.main(
        ["--", "aran-no-such-command-xyz", "--flag"],
        stdin=io.BytesIO(b""),
        stdout=io.BytesIO(),
    )

    assert code != 0
    err = capsys.readouterr().err
    assert "[Aran] failed to launch downstream server" in err
    assert "Traceback" not in err


# --- I4: a silent fallback to the built-in signatures is reported -----------

def test_main_warns_when_the_rules_file_is_missing(tmp_path, monkeypatch, capsys, fake_server_command):
    missing = tmp_path / "definitely-absent-rules.yaml"
    monkeypatch.setattr(cli, "DEFAULT_RULES_PATH", missing)
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")

    cli.main(["--", *fake_server_command], stdin=io.BytesIO(b""), stdout=io.BytesIO())

    err = capsys.readouterr().err
    assert "[Aran] warning: could not load" in err
    assert str(missing) in err
    assert "file not found" in err
    assert f"{len(DEFAULT_INPUT_SIGNATURES)} built-in input" in err


def test_main_warns_when_a_signature_key_is_malformed(tmp_path, monkeypatch, capsys, fake_server_command):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "input_gate_signatures: \"ignore previous instructions\"\n"
        "output_gate_signatures:\n  - \"rm\\\\s+-rf\"\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "DEFAULT_RULES_PATH", rules)
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")

    cli.main(["--", *fake_server_command], stdin=io.BytesIO(b""), stdout=io.BytesIO())

    err = capsys.readouterr().err
    assert "input_gate_signatures is not a list of strings" in err
    assert "built-in output" not in err  # the output key was fine


def test_main_is_silent_when_the_packaged_rules_file_loads(tmp_path, monkeypatch, capsys, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")

    cli.main(["--", *fake_server_command], stdin=io.BytesIO(b""), stdout=io.BytesIO(), env={})

    assert "warning" not in capsys.readouterr().err.lower()


# --- ARAN_MODE / ARAN_PROFILE: env-var parsing -------------------------------

@pytest.mark.parametrize("value", ["audit", "Audit", "AUDIT", " audit "])
def test_audit_only_enabled_accepts_case_and_whitespace_variants(value):
    assert cli.audit_only_enabled({"ARAN_MODE": value}) is True


@pytest.mark.parametrize("value", [None, "", "enforce", "audit-mode", "1"])
def test_audit_only_enabled_defaults_to_false(value):
    env = {} if value is None else {"ARAN_MODE": value}
    assert cli.audit_only_enabled(env) is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_profile_enabled_accepts_common_truthy_values(value):
    assert cli.profile_enabled({"ARAN_PROFILE": value}) is True


@pytest.mark.parametrize("value", [None, "", "0", "false", "False"])
def test_profile_enabled_defaults_to_false(value):
    env = {} if value is None else {"ARAN_PROFILE": value}
    assert cli.profile_enabled(env) is False


def test_main_prints_audit_mode_notice_and_does_not_block(tmp_path, monkeypatch, capsys, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}},
    }
    stdin = io.BytesIO((json.dumps(request) + "\n").encode("utf-8"))
    stdout = io.BytesIO()

    code = cli.main(
        ["--", *fake_server_command], stdin=stdin, stdout=stdout, env={"ARAN_MODE": "audit"}
    )

    assert code == 0
    response = json.loads(stdout.getvalue().decode("utf-8").strip())
    assert "error" not in response, "audit mode must never actually block"
    assert response["result"]["content"][0]["text"] == "ran run_command"
    err = capsys.readouterr().err
    assert "[Aran] audit mode" in err
    assert "ARAN_MODE=audit" in err


def test_main_does_not_print_audit_notice_by_default(tmp_path, monkeypatch, capsys, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")

    cli.main(["--", *fake_server_command], stdin=io.BytesIO(b""), stdout=io.BytesIO(), env={})

    assert "audit mode" not in capsys.readouterr().err.lower()


def test_main_wires_aran_profile_through_to_run_proxy(tmp_path, monkeypatch, capsys, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "list_files", "arguments": {}},
    }
    stdin = io.BytesIO((json.dumps(request) + "\n").encode("utf-8"))

    cli.main(
        ["--", *fake_server_command],
        stdin=stdin,
        stdout=io.BytesIO(),
        env={"ARAN_PROFILE": "1"},
    )

    assert "[Aran Profiler]" in capsys.readouterr().err


# --- ARAN_SCAN_GITHUB_REPOS: env-var parsing ---------------------------------

@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_scan_github_repos_enabled_accepts_common_truthy_values(value):
    assert cli.scan_github_repos_enabled({"ARAN_SCAN_GITHUB_REPOS": value}) is True


@pytest.mark.parametrize("value", [None, "", "0", "false", "False"])
def test_scan_github_repos_enabled_defaults_to_false(value):
    env = {} if value is None else {"ARAN_SCAN_GITHUB_REPOS": value}
    assert cli.scan_github_repos_enabled(env) is False


def test_main_prints_repo_scan_notice_when_enabled(tmp_path, monkeypatch, capsys, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")

    cli.main(
        ["--", *fake_server_command], stdin=io.BytesIO(b""), stdout=io.BytesIO(),
        env={"ARAN_SCAN_GITHUB_REPOS": "1"},
    )

    err = capsys.readouterr().err
    assert "[Aran] GitHub repo scan enabled" in err
    assert "ARAN_SCAN_GITHUB_REPOS=1" in err


def test_main_does_not_print_repo_scan_notice_by_default(tmp_path, monkeypatch, capsys, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")

    cli.main(["--", *fake_server_command], stdin=io.BytesIO(b""), stdout=io.BytesIO(), env={})

    assert "repo scan" not in capsys.readouterr().err.lower()


def test_main_does_not_scan_a_referenced_repo_unless_enabled(tmp_path, monkeypatch, capsys, fake_server_command):
    """Without ARAN_SCAN_GITHUB_REPOS set, a call that references a GitHub
    repo must be forwarded exactly as before this feature existed - no
    network call, no notice, no audit "detail" field."""
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    request = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "run_command", "arguments": {"command": "git clone https://github.com/octocat/demo-repo"}},
    }
    stdin = io.BytesIO((json.dumps(request) + "\n").encode("utf-8"))
    stdout = io.BytesIO()

    code = cli.main(["--", *fake_server_command], stdin=stdin, stdout=stdout, env={})

    assert code == 0
    response = json.loads(stdout.getvalue().decode("utf-8").strip())
    assert "error" not in response
    assert "repo scan" not in capsys.readouterr().err.lower()


# --- ~/.aran/allowlist.yaml: personal signature/trusted-repo overrides ------

def test_main_disables_a_signature_listed_in_the_allowlist(tmp_path, monkeypatch, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    allowlist_path = tmp_path / "allowlist.yaml"
    allowlist_path.write_text("allowed_signatures:\n  - 'rm\\s+-[rfRF]+'\n", encoding="utf-8")
    monkeypatch.setattr(cli, "DEFAULT_ALLOWLIST_PATH", allowlist_path)

    request = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}},
    }
    stdin = io.BytesIO((json.dumps(request) + "\n").encode("utf-8"))
    stdout = io.BytesIO()

    code = cli.main(["--", *fake_server_command], stdin=stdin, stdout=stdout, env={})

    assert code == 0
    response = json.loads(stdout.getvalue().decode("utf-8").strip())
    assert "error" not in response, "the allowlisted signature must not block the call"
    assert response["result"]["content"][0]["text"] == "ran run_command"


def test_main_prints_a_notice_when_the_allowlist_disables_signatures(tmp_path, monkeypatch, capsys, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    allowlist_path = tmp_path / "allowlist.yaml"
    allowlist_path.write_text("allowed_signatures:\n  - 'rm\\s+-[rfRF]+'\n", encoding="utf-8")
    monkeypatch.setattr(cli, "DEFAULT_ALLOWLIST_PATH", allowlist_path)

    cli.main(["--", *fake_server_command], stdin=io.BytesIO(b""), stdout=io.BytesIO(), env={})

    err = capsys.readouterr().err
    assert "signature(s) disabled by" in err
    assert str(allowlist_path) in err


def test_main_is_silent_about_the_allowlist_when_it_has_no_entries(tmp_path, monkeypatch, capsys, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(cli, "DEFAULT_ALLOWLIST_PATH", tmp_path / "does-not-exist.yaml")

    cli.main(["--", *fake_server_command], stdin=io.BytesIO(b""), stdout=io.BytesIO(), env={})

    assert "disabled by" not in capsys.readouterr().err.lower()


def test_main_leaves_signatures_not_named_in_the_allowlist_untouched(tmp_path, monkeypatch, fake_server_command):
    """An allowlist entry for a DIFFERENT signature must not weaken the one
    that actually matches this call."""
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    allowlist_path = tmp_path / "allowlist.yaml"
    allowlist_path.write_text('allowed_signatures:\n  - "some other pattern entirely"\n', encoding="utf-8")
    monkeypatch.setattr(cli, "DEFAULT_ALLOWLIST_PATH", allowlist_path)

    request = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}},
    }
    stdin = io.BytesIO((json.dumps(request) + "\n").encode("utf-8"))
    stdout = io.BytesIO()

    cli.main(["--", *fake_server_command], stdin=stdin, stdout=stdout, env={})

    response = json.loads(stdout.getvalue().decode("utf-8").strip())
    assert response["error"]["code"] == -32001


# --- ARAN_LOOP_GUARD: env-var parsing ----------------------------------------

@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_loop_guard_enabled_accepts_common_truthy_values(value):
    assert cli.loop_guard_enabled({"ARAN_LOOP_GUARD": value}) is True


@pytest.mark.parametrize("value", [None, "", "0", "false", "False"])
def test_loop_guard_enabled_defaults_to_false(value):
    env = {} if value is None else {"ARAN_LOOP_GUARD": value}
    assert cli.loop_guard_enabled(env) is False


def test_loop_guard_threshold_reads_the_env_var():
    assert cli.loop_guard_threshold({"ARAN_LOOP_GUARD_THRESHOLD": "5"}) == 5


def test_loop_guard_threshold_falls_back_on_missing_or_invalid():
    assert cli.loop_guard_threshold({}) == 20
    assert cli.loop_guard_threshold({"ARAN_LOOP_GUARD_THRESHOLD": "not a number"}) == 20


def test_loop_guard_window_seconds_reads_the_env_var():
    assert cli.loop_guard_window_seconds({"ARAN_LOOP_GUARD_WINDOW_SECONDS": "30"}) == 30.0


def test_loop_guard_window_seconds_falls_back_on_missing_or_invalid():
    assert cli.loop_guard_window_seconds({}) == 60.0
    assert cli.loop_guard_window_seconds({"ARAN_LOOP_GUARD_WINDOW_SECONDS": "nope"}) == 60.0


def test_main_prints_loop_guard_notice_when_enabled(tmp_path, monkeypatch, capsys, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")

    cli.main(
        ["--", *fake_server_command], stdin=io.BytesIO(b""), stdout=io.BytesIO(),
        env={"ARAN_LOOP_GUARD": "1"},
    )

    err = capsys.readouterr().err
    assert "loop guard enabled" in err
    assert "ARAN_LOOP_GUARD=1" in err


def test_main_does_not_print_loop_guard_notice_by_default(tmp_path, monkeypatch, capsys, fake_server_command):
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")

    cli.main(["--", *fake_server_command], stdin=io.BytesIO(b""), stdout=io.BytesIO(), env={})

    assert "loop guard" not in capsys.readouterr().err.lower()


def test_main_wires_loop_guard_threshold_through_to_run_proxy(tmp_path, monkeypatch, fake_server_command):
    """An end-to-end check that a custom threshold from the env actually
    reaches run_proxy, not just that the env-var parsing functions work in
    isolation."""
    monkeypatch.setattr(cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    calls = [
        {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}}
        for i in range(1, 4)
    ]
    stdin = io.BytesIO(("".join(json.dumps(c) + "\n" for c in calls)).encode("utf-8"))
    stdout = io.BytesIO()

    cli.main(
        ["--", *fake_server_command], stdin=stdin, stdout=stdout,
        env={"ARAN_LOOP_GUARD": "1", "ARAN_LOOP_GUARD_THRESHOLD": "2"},
    )

    responses = [json.loads(line) for line in stdout.getvalue().decode("utf-8").splitlines() if line.strip()]
    # Response order in stdout isn't guaranteed to match request order
    # (blocked responses are synthesized immediately, allowed ones
    # round-trip through the child process on a separate thread) - look
    # each one up by id.
    by_id = {r["id"]: r for r in responses}
    assert "error" not in by_id[1]
    assert by_id[2]["error"]["code"] == -32003
    assert by_id[3]["error"]["code"] == -32003
