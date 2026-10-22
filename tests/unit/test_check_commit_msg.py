import subprocess
import sys
from pathlib import Path

import check_commit_msg as check
import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_commit_msg.py"


@pytest.mark.phase(0)
@pytest.mark.parametrize(
    "subject",
    [
        "feat(policy): require approval for transfers over the tenant limit",
        "fix(gateway): close the upstream session in the task that opened it",
        "chore: bump the lockfile",
        "docs(repo): add the runbook and mark ks-002 done",
        "ci(repo): pin runners to ubuntu-24.04",
        "build(deploy): add the multi-stage image and the ci dev dependencies",
        "feat(admin)!: drop the --legacy flag",
        "feat(db): embed the schema version in the health response",
        "Merge branch 'feat/ks-004-settings-health' into dev",
        "Release v0.0.1: Phase 0 Foundation",
    ],
)
def test_accepts_good_subjects(subject: str) -> None:
    assert check.problems(subject) == []


@pytest.mark.phase(0)
def test_rejects_a_subject_over_72_characters() -> None:
    subject = "feat(gateway): " + "x" * 58

    assert len(subject) == 73
    assert any("73 characters" in message for message in check.problems(subject))
    assert check.problems(subject[:-1]) == []


@pytest.mark.phase(0)
@pytest.mark.parametrize(
    ("subject", "fragment"),
    [
        ("add the runbook", "expected 'type(scope): summary'"),
        ("Fix: add the runbook", "expected 'type(scope): summary'"),
        ("feature(repo): add the runbook", "unknown type"),
        ("feat(repo):add the runbook", "expected 'type(scope): summary'"),
        ("feat(repo): Add the runbook", "lowercase"),
        ("feat(repo): added the runbook", "not imperative"),
        ("feat(repo): adding the runbook", "not imperative"),
        ("feat(repo): adds the runbook", "not imperative"),
        ("feat(repo): fixes the runbook", "not imperative"),
        ("feat(repo): add the runbook.", "trailing period"),
        ("", "empty"),
    ],
)
def test_rejects_bad_subjects(subject: str, fragment: str) -> None:
    messages = check.problems(subject) if subject else ["the commit message is empty"]

    assert any(fragment in message for message in messages), messages


@pytest.mark.phase(0)
def test_cli_reads_a_message_file_and_skips_comment_lines(tmp_path: Path) -> None:
    good = tmp_path / "good"
    good.write_text("# comment\n\nfeat(repo): add a thing\n\nbody\n\nRefs: KS-001\n")
    bad = tmp_path / "bad"
    bad.write_text("Added a thing\n")

    run = lambda arg: subprocess.run(  # noqa: E731
        [sys.executable, str(SCRIPT), str(arg)], capture_output=True, text=True, check=False
    )

    assert run(good).returncode == 0
    failed = run(bad)
    assert failed.returncode == 1
    assert "expected 'type(scope): summary'" in failed.stderr


@pytest.mark.phase(0)
def test_cli_accepts_a_subject_string_and_reports_annotations_in_ci(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "nope"],
        capture_output=True,
        text=True,
        check=False,
        env={"GITHUB_ACTIONS": "true", "PATH": ""},
    )

    assert result.returncode == 1
    assert result.stdout.startswith("::error title=commit subject::")
