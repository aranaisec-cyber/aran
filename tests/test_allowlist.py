from pathlib import Path

from aran.allowlist import filter_signatures, is_trusted_repo, load_allowlist


def test_load_allowlist_missing_file_returns_empty(tmp_path: Path):
    allowlist = load_allowlist(tmp_path / "nope.yaml")

    assert allowlist.signatures == set()
    assert allowlist.trusted_repos == set()


def test_load_allowlist_reads_both_keys(tmp_path: Path):
    path = tmp_path / "allowlist.yaml"
    path.write_text(
        "allowed_signatures:\n  - 'rm\\s+-rf'\n  - 'some phrase'\n"
        "trusted_repos:\n  - octocat/demo\n  - myorg/*\n",
        encoding="utf-8",
    )

    allowlist = load_allowlist(path)

    assert allowlist.signatures == {r"rm\s+-rf", "some phrase"}
    assert allowlist.trusted_repos == {"octocat/demo", "myorg/*"}


def test_load_allowlist_empty_file_returns_empty(tmp_path: Path):
    path = tmp_path / "allowlist.yaml"
    path.write_text("", encoding="utf-8")

    allowlist = load_allowlist(path)

    assert allowlist.signatures == set()


def test_load_allowlist_malformed_yaml_returns_empty_not_raises(tmp_path: Path):
    path = tmp_path / "allowlist.yaml"
    path.write_text("allowed_signatures: [unterminated", encoding="utf-8")

    allowlist = load_allowlist(path)

    assert allowlist.signatures == set()
    assert allowlist.trusted_repos == set()


def test_load_allowlist_non_mapping_yaml_returns_empty(tmp_path: Path):
    path = tmp_path / "allowlist.yaml"
    path.write_text("just a string, not a mapping", encoding="utf-8")

    allowlist = load_allowlist(path)

    assert allowlist.signatures == set()


def test_load_allowlist_ignores_a_malformed_key_value(tmp_path: Path):
    path = tmp_path / "allowlist.yaml"
    path.write_text("allowed_signatures: \"not a list\"\ntrusted_repos:\n  - octocat/demo\n", encoding="utf-8")

    allowlist = load_allowlist(path)

    assert allowlist.signatures == set()  # malformed key ignored, not split per-character
    assert allowlist.trusted_repos == {"octocat/demo"}


def test_load_allowlist_ignores_non_string_list_elements(tmp_path: Path):
    path = tmp_path / "allowlist.yaml"
    path.write_text("allowed_signatures:\n  - one\n  - 123\n", encoding="utf-8")

    allowlist = load_allowlist(path)

    assert allowlist.signatures == {"one"}


def test_filter_signatures_drops_allowed_entries():
    result = filter_signatures(["a", "b", "c"], {"b"})
    assert result == ["a", "c"]


def test_filter_signatures_empty_allowlist_returns_everything():
    result = filter_signatures(["a", "b"], set())
    assert result == ["a", "b"]


def test_filter_signatures_preserves_order():
    result = filter_signatures(["z", "a", "m"], {"a"})
    assert result == ["z", "m"]


def test_is_trusted_repo_exact_match():
    assert is_trusted_repo("octocat", "demo", {"octocat/demo"}) is True


def test_is_trusted_repo_case_insensitive():
    assert is_trusted_repo("OctoCat", "Demo", {"octocat/demo"}) is True


def test_is_trusted_repo_wildcard_owner():
    assert is_trusted_repo("myorg", "anything", {"myorg/*"}) is True
    assert is_trusted_repo("other-org", "anything", {"myorg/*"}) is False


def test_is_trusted_repo_no_match():
    assert is_trusted_repo("octocat", "demo", {"someone-else/repo"}) is False


def test_is_trusted_repo_empty_allowlist():
    assert is_trusted_repo("octocat", "demo", set()) is False
