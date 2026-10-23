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


def jobs() -> dict[str, Any]:
    found: dict[str, Any] = workflow()["jobs"]
    return found


def commands(job: str = "e2e") -> list[str]:
    return [step["run"] for step in jobs()[job]["steps"] if "run" in step]


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
    job = jobs()["e2e"]

    assert document["permissions"] == {"contents": "read"}
    assert job["timeout-minutes"] <= 60
    assert any(
        step.get("if") == "always()" and step.get("run") == "make down" for step in job["steps"]
    )
    assert all(each["timeout-minutes"] <= 60 for each in jobs().values())


@pytest.mark.phase(3)
def test_it_uses_the_pinned_actions_of_the_ci_workflow() -> None:
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    ci_actions = {
        step["uses"] for job in ci["jobs"].values() for step in job["steps"] if "uses" in step
    }
    used = {step["uses"] for job in jobs().values() for step in job["steps"] if "uses" in step}

    assert used and used <= ci_actions


@pytest.mark.phase(6)
def test_it_drives_the_console_in_a_browser_once_the_stack_is_up() -> None:
    steps = commands()

    assert steps.index("make up") < steps.index("make console-e2e")
    assert any("playwright install --with-deps chromium" in step for step in steps)


@pytest.mark.phase(7)
def test_the_detector_job_scores_200_samples_with_the_rules_and_no_model() -> None:
    steps = commands("detector")
    evaluation = [step for step in steps if "eval.detector.run" in step]
    text = "\n".join(steps)

    assert set(jobs()) == {"e2e", "detector"}
    assert len(evaluation) == 1
    for flag in ("--config rules", "--split dev", "--limit 200"):
        assert flag in evaluation[0], flag
    # No model in CI: the scanner extra is not installed, and nothing downloads weights.
    assert "scanner" not in text and "huggingface" not in text.lower()
    assert "uv sync --extra eval" in steps
    # The test split is for the published numbers: a nightly run reads dev.
    assert "--split test" not in text


@pytest.mark.phase(7)
def test_the_detector_job_fails_when_the_rules_rank_worse_than_the_guard() -> None:
    [evaluation] = [step for step in commands("detector") if "eval.detector.run" in step]

    match = re.search(r"--fail-under-auc (\d\.\d+)", evaluation)

    assert match is not None
    assert 0.5 < float(match.group(1)) < 0.9
    assert "set -o pipefail" in evaluation  # the pipe to the summary must not hide a failure
