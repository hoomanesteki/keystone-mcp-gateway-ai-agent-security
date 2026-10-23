"""The nightly workflow runs what a developer runs by hand: `make up`, then the e2e tests."""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / ".github" / "workflows" / "nightly.yml"


def workflow() -> dict[Any, Any]:
    loaded: dict[Any, Any] = yaml.safe_load(PATH.read_text())
    return loaded


def triggers() -> dict[str, Any]:
    document = workflow()
    # PyYAML reads the bare key `on` as the boolean True.
    on: dict[str, Any] = document["on" if "on" in document else True]
    return on


def commands() -> list[str]:
    [job] = workflow()["jobs"].values()
    return [step["run"] for step in job["steps"] if "run" in step]


@pytest.mark.phase(3)
def test_it_runs_on_a_schedule_and_by_hand_only() -> None:
    on = triggers()

    assert set(on) == {"schedule", "workflow_dispatch"}
    [entry] = on["schedule"]
    assert re.fullmatch(r"\d+ \d+ \* \* \*", entry["cron"]), "once a day"


@pytest.mark.phase(3)
def test_it_starts_the_stack_and_then_runs_the_e2e_tests() -> None:
    steps = commands()

    assert steps.index("make up") < steps.index("make test-e2e")
    assert steps[0] == "uv sync"


@pytest.mark.phase(3)
def test_every_make_target_it_uses_exists() -> None:
    makefile = (ROOT / "Makefile").read_text()

    for line in commands():
        match = re.fullmatch(r"make (\S+)", line)
        if match:
            assert re.search(rf"^{re.escape(match.group(1))}:", makefile, re.MULTILINE), line


@pytest.mark.phase(3)
def test_it_has_least_privilege_and_a_time_limit_and_stops_the_stack() -> None:
    document = workflow()
    [job] = document["jobs"].values()

    assert document["permissions"] == {"contents": "read"}
    assert job["timeout-minutes"] <= 60
    assert any(
        step.get("if") == "always()" and step.get("run") == "make down" for step in job["steps"]
    )


@pytest.mark.phase(3)
def test_it_uses_the_pinned_actions_of_the_ci_workflow() -> None:
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    ci_actions = {
        step["uses"] for job in ci["jobs"].values() for step in job["steps"] if "uses" in step
    }
    [job] = workflow()["jobs"].values()
    used = {step["uses"] for step in job["steps"] if "uses" in step}

    assert used and used <= ci_actions
