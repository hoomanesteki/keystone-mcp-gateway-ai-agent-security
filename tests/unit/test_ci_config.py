import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
# PyYAML reads the bare key `on` as the boolean True.
TRIGGERS = WORKFLOW.get("on", WORKFLOW.get(True))


@pytest.mark.phase(0)
def test_workflow_triggers_and_concurrency() -> None:
    assert TRIGGERS["push"]["branches"] == ["**"]
    assert TRIGGERS["pull_request"]["branches"] == ["dev", "main"]
    assert WORKFLOW["concurrency"]["cancel-in-progress"] is True
    assert "github.ref" in WORKFLOW["concurrency"]["group"]


@pytest.mark.phase(0)
def test_workflow_has_the_planned_jobs() -> None:
    assert set(WORKFLOW["jobs"]) == {
        "lint-type",
        "unit",
        "policy",
        "integration",
        "security",
        "docker",
        "commits",
        "docs",
    }
    for job_id, job in WORKFLOW["jobs"].items():
        assert job["name"] == job_id, "required-check names must equal the job ids"


@pytest.mark.phase(0)
def test_integration_services_map_to_the_default_settings_ports() -> None:
    services = WORKFLOW["jobs"]["integration"]["services"]

    assert services["postgres"]["ports"] == ["55432:5432"]
    assert services["redis"]["ports"] == ["56379:6379"]


@pytest.mark.phase(0)
def test_failure_annotations_are_wired() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "--output-format=github" in text
    assert "::error title=mypy,file=" in text
    assert WORKFLOW["defaults"]["run"]["shell"] == "bash"  # bash adds pipefail


@pytest.mark.phase(0)
def test_protect_branches_requires_every_ci_job() -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "protect_branches.sh"), "--dry-run"],
        capture_output=True,
        text=True,
        check=True,
    )

    listed = re.search(r'"contexts": \[(.*?)\]', result.stdout)
    assert listed is not None
    contexts = set(re.findall(r'"([a-z-]+)"', listed.group(1)))
    assert contexts == set(WORKFLOW["jobs"])
    assert '"allow_force_pushes": false' in result.stdout
    assert result.stdout.count("branches/main/protection") == 1
    assert result.stdout.count("branches/dev/protection") == 1


@pytest.mark.phase(0)
def test_publish_releases_rejects_an_unknown_tag_and_a_missing_report(tmp_path: Path) -> None:
    script = str(ROOT / "scripts" / "publish_releases.sh")

    unknown = subprocess.run(["bash", script, "v9.9.9"], capture_output=True, text=True)
    missing = subprocess.run(
        ["bash", script, "v0.3.0", "--dry-run"], capture_output=True, text=True, cwd=tmp_path
    )

    assert unknown.returncode == 2
    assert missing.returncode == 1
    assert "docs/gates/phase-3.md" in missing.stderr
