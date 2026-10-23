"""scripts/dev_env.sh: the environment beats .env, which beats .env.example."""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "dev_env.sh"


def load(directory: Path, names: list[str], env: dict[str, str] | None = None) -> dict[str, str]:
    script = f'. "{HELPER}"; load_dev_env "{directory}"; ' + "; ".join(
        f'echo "{name}=${{{name}-<unset>}}"' for name in names
    )
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": "/usr/bin:/bin", **(env or {})},
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


@pytest.mark.phase(3)
def test_the_environment_beats_dot_env_which_beats_the_example(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("A=example\nB=example\nC=example\n# D=comment\n")
    (tmp_path / ".env").write_text("B=dotenv\nC=dotenv\n")

    seen = load(tmp_path, ["A", "B", "C", "D"], env={"C": "environment"})

    assert seen == {"A": "example", "B": "dotenv", "C": "environment", "D": "<unset>"}


@pytest.mark.phase(3)
def test_a_value_is_data_and_never_a_command(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    (tmp_path / ".env.example").write_text(
        f"X=$(touch {marker})\nY=`touch {marker}`\nZ=a=b\nnot a line\nbad-name=1\n"
    )

    seen = load(tmp_path, ["X", "Z"])

    assert not marker.exists()
    assert seen["X"] == f"$(touch {marker})"
    assert seen["Z"] == "a=b"


@pytest.mark.phase(3)
def test_a_missing_file_is_fine(tmp_path: Path) -> None:
    assert load(tmp_path, ["A"]) == {"A": "<unset>"}
