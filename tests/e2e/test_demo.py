import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy" / "docker-compose.yml")]

pytestmark = [pytest.mark.phase(1), pytest.mark.e2e, pytest.mark.docker]


@pytest.fixture(scope="module")
def stack() -> Iterator[None]:
    # `up --wait` is idempotent, and --build picks up source changes.
    subprocess.run([*COMPOSE, "up", "-d", "--build", "--wait"], check=True, timeout=900)
    yield


def test_demo_p1_script(stack: None) -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "smoke" / "phase_1.sh")],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    ok_calls = [line for line in lines if line.startswith(("2. ok", "3. ok", "4. ok"))]
    assert [line.split()[2] for line in ok_calls] == [
        "bank__get_balance",
        "mail__send_email",
        "mail__read_email",
    ]
    assert "audit records added: 3, tool calls made: 3, steps ok: 4 of 4" in result.stdout
    assert "call_id 01" in result.stdout
