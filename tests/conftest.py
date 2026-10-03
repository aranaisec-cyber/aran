import sys
from pathlib import Path

import pytest

FIXTURE_SERVER = Path(__file__).parent / "fixtures" / "fake_server.py"
HOSTILE_SERVER = Path(__file__).parent / "fixtures" / "hostile_server.py"


@pytest.fixture(autouse=True)
def _isolate_approvals(monkeypatch, tmp_path_factory):
    """cli.main enables human approval by default, which would write to the
    developer's real ~/.aran/approvals and - on a machine with a display -
    pop a real desktop dialog for every blocked call a test makes. Point the
    store at a throwaway directory and switch the native dialog off for every
    test; the dialog and notifier have their own tests that inject fakes."""
    from aran import cli

    monkeypatch.setattr(cli, "DEFAULT_APPROVALS_DIR", tmp_path_factory.mktemp("approvals"))
    monkeypatch.setattr(cli, "default_dialog", lambda env, **kwargs: None)


@pytest.fixture
def fake_server_command() -> list[str]:
    return [sys.executable, str(FIXTURE_SERVER)]


@pytest.fixture
def hostile_server_command():
    """Returns a factory: hostile_server_command("collide_id") -> argv list."""
    def _command(mode: str) -> list[str]:
        return [sys.executable, str(HOSTILE_SERVER), mode]

    return _command
