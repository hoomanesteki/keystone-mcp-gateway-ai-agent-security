import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy" / "docker-compose.yml")]

pytestmark = [pytest.mark.phase(5), pytest.mark.e2e, pytest.mark.docker]


@pytest.fixture(scope="module")
def stack() -> Iterator[None]:
    # `up --wait` is idempotent, and --build picks up source changes.
    subprocess.run([*COMPOSE, "up", "-d", "--build", "--wait"], check=True, timeout=900)
    yield


def test_phase_5_smoke(stack: None) -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "smoke" / "phase_5.sh")],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "audit records added: 3, tool calls made: 3, steps ok: 4 of 4" in out
    assert "leaks: none" in out
    assert (
        "keystone_tool_calls_total:" in out and "Prometheus: sum(keystone_tool_calls_total)" in out
    )
    assert "Grafana dashboard (provisioned, panels): True" in out
    assert "OK, " in out and "(exit 2)" in out and "broken at seq" in out
    assert "phase 5 smoke: ok" in out
