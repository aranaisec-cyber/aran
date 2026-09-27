"""I3: the signature file must be found the same way in an editable install
and in a real wheel install, and it must actually be declared as package data.
"""
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    tomllib = None

import aran
from aran import cli
from aran.rules import DEFAULT_INPUT_SIGNATURES, load_rules_detailed

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_default_rules_path_is_inside_the_installed_package():
    package_dir = Path(aran.__file__).resolve().parent
    rules_path = cli.default_rules_path().resolve()

    assert rules_path.parent == package_dir
    assert rules_path.exists(), (
        "the rules file must live inside the package so a non-editable install ships it"
    )


def test_packaged_rules_file_loads_the_full_signature_set():
    result = load_rules_detailed(cli.default_rules_path())

    assert not result.used_fallback, result.fallback_reasons
    # The generated profile has hundreds of signatures; the built-in fallback
    # has four. Anything near four means we are silently unprotected.
    assert len(result.input_signatures) > len(DEFAULT_INPUT_SIGNATURES) * 10
    assert len(result.output_signatures) >= 10


def test_every_packaged_signature_compiles():
    import re

    result = load_rules_detailed(cli.default_rules_path())
    for signature in result.input_signatures + result.output_signatures:
        re.compile(signature)


@pytest.mark.skipif(tomllib is None, reason="tomllib requires Python 3.11+")
def test_pyproject_declares_the_rules_file_as_package_data():
    with open(PROJECT_ROOT / "pyproject.toml", "rb") as f:
        pyproject = tomllib.load(f)

    package_data = pyproject["tool"]["setuptools"]["package-data"]
    assert "default-rules.yaml" in package_data["aran"]


def test_no_stale_repo_root_config_copy_remains():
    # Two copies would drift; the packaged one is the single source of truth.
    assert not (PROJECT_ROOT / "config" / "default-rules.yaml").exists()


def test_sync_script_writes_to_the_packaged_location():
    script = (PROJECT_ROOT / "scripts" / "sync_threat_intel.py").read_text(encoding="utf-8")
    assert "src/aran/default-rules.yaml" in script
