"""The Phase 9 smoke runs the eight before it in order against one stack, and the gate runs it once.

The smoke scripts need the compose stack, so these tests give `phase_9.sh` a folder of scripts that
do nothing but note that they ran, and read the loop of `make gate` without running it.
"""

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.phase(9)

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "smoke" / "phase_9.sh"


def folder(tmp_path: Path, failing: tuple[int, ...] = (), missing: tuple[int, ...] = ()) -> Path:
    smoke = tmp_path / "smoke"
    smoke.mkdir()
    log = tmp_path / "ran.txt"
    for k in range(9):
        if k in missing:
            continue
        (smoke / f"phase_{k}.sh").write_text(
            f"#!/usr/bin/env bash\necho {k} >> '{log}'\nexit {1 if k in failing else 0}\n"
        )
    return smoke


def run(smoke: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "SMOKE_DIR": str(smoke), "SMOKE_SKIP_STACK_CHECK": "1", **env},
        cwd=ROOT,
    )


def test_it_is_a_script_that_bash_accepts_and_can_run() -> None:
    assert SCRIPT.stat().st_mode & stat.S_IXUSR
    assert subprocess.run(["bash", "-n", str(SCRIPT)], check=False).returncode == 0


def test_it_runs_the_smokes_of_phases_0_to_8_in_order_and_ends_with_the_list(
    tmp_path: Path,
) -> None:
    smoke = folder(tmp_path)

    done = run(smoke)

    assert done.returncode == 0, done.stderr
    assert (tmp_path / "ran.txt").read_text().split() == [str(k) for k in range(9)]
    assert "ok:     0 1 2 3 4 5 6 7 8" in done.stdout and "every smoke passed" in done.stdout
    assert [m for m in re.findall(r"== smoke: phase (\d)", done.stdout)] == list("012345678")


def test_it_runs_the_rest_when_one_fails_and_says_which(tmp_path: Path) -> None:
    smoke = folder(tmp_path, failing=(3, 7))

    done = run(smoke)

    # The eight ran, so that a gate says every phase that is broken and not only the first.
    assert done.returncode == 1
    assert (tmp_path / "ran.txt").read_text().split() == [str(k) for k in range(9)]
    assert "FAILED: 3 7" in done.stderr and "ok:     0 1 2 4 5 6 8" in done.stdout
    assert "every smoke passed" not in done.stdout


def test_a_smoke_that_is_missing_is_a_failure_and_not_a_pass(tmp_path: Path) -> None:
    smoke = folder(tmp_path, missing=(5,))

    done = run(smoke)

    assert done.returncode == 1
    assert "phase_5.sh does not exist" in done.stderr and "FAILED: 5" in done.stderr


def test_it_says_so_when_the_stack_is_not_up(tmp_path: Path) -> None:
    smoke = folder(tmp_path)

    done = subprocess.run(
        ["bash", str(SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "SMOKE_DIR": str(smoke), "KEYSTONE_PORT": "1"},
        cwd=ROOT,
    )

    assert done.returncode == 1
    assert "Is the stack up (make up)?" in done.stderr
    assert not (tmp_path / "ran.txt").exists()  # nothing was run against a stack that is not there


def smokes_of_the_gate(phase: int, tmp_path: Path) -> list[str]:
    """The smoke scripts that `make gate PHASE=<phase>` would run, from the loop of its recipe, with
    each `bash <script>` replaced by an `echo` of the name. Nothing is run."""
    plan = subprocess.run(
        ["make", "-n", "gate", f"PHASE={phase}"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    ).stdout
    lines = plan.splitlines()
    first = next(i for i, line in enumerate(lines) if line.startswith("k=0; while"))
    last = next(i for i in range(first, len(lines)) if lines[i].strip() == "done")
    echoed = "\n".join(lines[first : last + 1]).replace("bash $f", "echo ran $f")
    shown = subprocess.run(
        ["bash", "-c", echoed], capture_output=True, text=True, cwd=ROOT, check=False
    )
    return re.findall(r"ran (scripts/smoke/phase_\d\.sh)", shown.stdout)


@pytest.mark.parametrize(
    ("phase", "expected"),
    [(3, [0, 1, 2, 3]), (8, list(range(9))), (9, [9])],
)
def test_the_gate_runs_every_smoke_up_to_its_phase_and_for_9_the_one_that_runs_the_rest(
    tmp_path: Path, phase: int, expected: list[int]
) -> None:
    assert smokes_of_the_gate(phase, tmp_path) == [f"scripts/smoke/phase_{k}.sh" for k in expected]
