import sys
from pathlib import Path

import pytest

FIXTURE_SERVER = Path(__file__).parent / "fixtures" / "fake_server.py"
HOSTILE_SERVER = Path(__file__).parent / "fixtures" / "hostile_server.py"


@pytest.fixture
def fake_server_command() -> list[str]:
    return [sys.executable, str(FIXTURE_SERVER)]


@pytest.fixture
def hostile_server_command():
    """Returns a factory: hostile_server_command("collide_id") -> argv list."""
    def _command(mode: str) -> list[str]:
        return [sys.executable, str(HOSTILE_SERVER), mode]

    return _command
