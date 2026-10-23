import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy" / "docker-compose.yml")]

pytestmark = [pytest.mark.phase(3), pytest.mark.e2e, pytest.mark.docker]


@pytest.fixture(scope="module")
def stack() -> Iterator[None]:
    # `up --wait` is idempotent, and --build picks up source changes.
    subprocess.run([*COMPOSE, "up", "-d", "--build", "--wait"], check=True, timeout=900)
    yield


def test_phase_3_smoke(stack: None) -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "smoke" / "phase_3.sh")],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "alice through support-agent: sub=alice tenant=acme azp=support-agent" in out
    assert "bob through support-agent: sub=bob tenant=globex azp=support-agent" in out
    assert "HTTP/1.1 401" in out
    assert "tools: 18" in out and "tools: 5" in out
    assert "code=KS_TOOL_NOT_FOUND" in out
    assert "api_key_received=true" in out
    assert "KEYSTONE_MASTER_KEYS: 0 occurrences" in out
    assert "phase 3 smoke: ok" in out
