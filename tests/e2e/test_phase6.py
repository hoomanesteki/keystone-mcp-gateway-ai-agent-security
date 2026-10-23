import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy" / "docker-compose.yml")]

pytestmark = [pytest.mark.phase(6), pytest.mark.e2e, pytest.mark.docker]


@pytest.fixture(scope="module")
def stack() -> Iterator[None]:
    # `up --wait` is idempotent, and --build picks up source changes.
    subprocess.run([*COMPOSE, "up", "-d", "--build", "--wait"], check=True, timeout=900)
    yield


def test_phase_6_smoke(stack: None) -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "smoke" / "phase_6.sh")],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    # A transfer of 900 is approved by lena and completes; olivia may not decide, and a second
    # decision is refused.
    assert "reasons ['approve-transfer-over-500']" in out
    assert "olivia deciding her own request: 403" in out
    assert "lena approves: 200 approved" in out and "a second decision: 409" in out
    assert "transfers at the bank: 900.0" in out
    # One is rejected with a note, which the agent gets.
    assert "lena rejects: 200 rejected" in out and "KS_APPROVAL_REJECTED" in out
    assert "not this quarter" in out
    # One is told it is pending, then approved late and awaited.
    assert "the agent was told KS_APPROVAL_PENDING" in out
    assert "transfers at the bank: 900.0,600.0" in out
    assert "ran=2 effect=require_approval rejected=1 pending=1 awaits_virtual=True" in out
    assert "phase 6 smoke: ok" in out
