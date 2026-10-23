import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy" / "docker-compose.yml")]

pytestmark = [pytest.mark.phase(2), pytest.mark.e2e, pytest.mark.docker]


@pytest.fixture(scope="module")
def stack() -> Iterator[None]:
    # `up --wait` is idempotent, and --build picks up source changes.
    subprocess.run([*COMPOSE, "up", "-d", "--build", "--wait"], check=True, timeout=900)
    yield


def test_phase_2_smoke(stack: None) -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "smoke" / "phase_2.sh")],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        env={**os.environ, "SMOKE_HEALTH_INTERVAL_S": "2"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "tools: 18" in out
    assert "changed: echo__echo (quarantined)" in out
    assert "code=KS_QUARANTINED" in out
    assert "approved echo__echo" in out
    assert "upstream bank is down" in out
    assert "phase 2 smoke: ok" in out
