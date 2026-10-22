import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy" / "docker-compose.yml")]
SERVICES = {"postgres", "redis", "keycloak", "jaeger", "prometheus", "grafana"}

pytestmark = [pytest.mark.phase(0), pytest.mark.e2e, pytest.mark.docker]


@pytest.fixture(scope="module")
def stack() -> Iterator[None]:
    # `up --wait` is idempotent, so the test works with or without a running stack.
    subprocess.run([*COMPOSE, "up", "-d", "--wait"], check=True, timeout=240)
    yield


def service_states() -> dict[str, dict[str, str]]:
    out = subprocess.run(
        [*COMPOSE, "ps", "--all", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    rows = [json.loads(line) for line in out.splitlines() if line.strip()]
    return {row["Service"]: row for row in rows}


def test_all_services_healthy(stack: None) -> None:
    states = service_states()

    assert states.keys() >= SERVICES
    unhealthy = {
        name: (states[name]["State"], states[name].get("Health"))
        for name in SERVICES
        if states[name]["State"] != "running" or states[name].get("Health") != "healthy"
    }
    assert unhealthy == {}


def test_smoke_script_prints_six_healthy_rows(stack: None) -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "smoke" / "phase_0.sh")],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    healthy_rows = [
        line for line in result.stdout.splitlines() if line.rstrip().endswith("healthy")
    ]
    assert len(healthy_rows) == 6
