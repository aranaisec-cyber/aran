import sys
from pathlib import Path

import pytest

FIXTURE_SERVER = Path(__file__).parent / "fixtures" / "fake_server.py"


@pytest.fixture
def fake_server_command() -> list[str]:
    return [sys.executable, str(FIXTURE_SERVER)]
