import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy" / "docker-compose.yml")]

pytestmark = [pytest.mark.phase(4), pytest.mark.e2e, pytest.mark.docker]


@pytest.fixture(scope="module")
def stack() -> Iterator[None]:
    # `up --wait` is idempotent, and --build picks up source changes.
    subprocess.run([*COMPOSE, "up", "-d", "--build", "--wait"], check=True, timeout=900)
    yield


def test_phase_4_smoke(stack: None) -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "smoke" / "phase_4.sh")],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "denied by policy: default-deny" in out
    assert "audit: deny default-deny" in out
    assert "tools: 16" in out
    assert "audit: require_approval approve-transfer-over-500" in out
    assert "lena rejects: 200" in out and "code=KS_APPROVAL_REJECTED" in out  # held, then rejected
    assert "audit: allow operators-high" in out
    assert "transfers at the bank: 1" in out
    assert "reload: 422" in out and "stays in force" in out
    assert "phase 4 smoke: ok" in out
