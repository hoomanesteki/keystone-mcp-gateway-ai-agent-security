from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

REQUIRED = [
    "LICENSE",
    "README.md",
    "CONTRIBUTING.md",
    "docs/PLAN.md",
    "docs/progress.md",
    "docs/runbook.md",
    "docs/adr/0001-record-decisions.md",
    "docs/adr/0002-dependency-pins.md",
    ".github/pull_request_template.md",
    "scripts/check_commit_msg.py",
    "scripts/lint_prose.py",
]


@pytest.mark.phase(0)
def test_required_docs_present() -> None:
    missing = [name for name in REQUIRED if not (ROOT / name).is_file()]
    assert missing == []

    plan = (ROOT / "docs" / "PLAN.md").read_text()
    assert "#### KS-001 · Repo scaffold and toolchain" in plan


@pytest.mark.phase(0)
def test_contributing_is_plan_section_5_8_verbatim() -> None:
    plan = (ROOT / "docs" / "PLAN.md").read_text().splitlines()
    heading = next(i for i, line in enumerate(plan) if line.startswith("### 5.8 "))
    start = plan.index("```markdown", heading) + 1
    end = plan.index("```", start)

    assert (ROOT / "CONTRIBUTING.md").read_text() == "\n".join(plan[start:end]) + "\n"


@pytest.mark.phase(0)
def test_pull_request_template_has_the_planned_sections() -> None:
    text = (ROOT / ".github" / "pull_request_template.md").read_text()

    assert [line for line in text.splitlines() if line.startswith("## ")] == [
        "## What",
        "## Why",
        "## How I tested it",
        "## Notes",
    ]


@pytest.mark.phase(0)
def test_license_stays_mit() -> None:
    assert (ROOT / "LICENSE").read_text().startswith("MIT License")
    assert 'license = "MIT"' in (ROOT / "pyproject.toml").read_text()
