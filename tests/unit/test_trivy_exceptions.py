"""KS-906: the image scan runs in CI, and every finding it is told to ignore says why."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
EXCEPTIONS = yaml.safe_load((ROOT / ".trivyignore.yaml").read_text())


@pytest.mark.phase(9)
def test_the_security_job_scans_the_image_for_high_and_critical_findings() -> None:
    assert "trivy image" in WORKFLOW
    assert "--severity HIGH,CRITICAL" in WORKFLOW
    assert "--exit-code 1" in WORKFLOW
    assert "--ignorefile .trivyignore.yaml" in WORKFLOW
    assert "TRIVY_SHA256" in WORKFLOW  # the download is checked, as gitleaks' is


@pytest.mark.phase(9)
def test_every_ignored_finding_has_a_reason_and_a_scope() -> None:
    entries = EXCEPTIONS["vulnerabilities"]
    assert entries, "an empty list means the file should be deleted"
    for entry in entries:
        assert entry["id"].startswith("CVE-")
        assert len(entry["statement"]) >= 20, entry["id"]
        assert entry.get("purls") or entry.get("paths"), f"{entry['id']} is ignored everywhere"


@pytest.mark.phase(9)
def test_no_finding_is_ignored_twice() -> None:
    ids = [entry["id"] for entry in EXCEPTIONS["vulnerabilities"]]
    assert len(ids) == len(set(ids))
