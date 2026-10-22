from pathlib import Path

import plan_parser
import progress_sync
import pytest

PLAN = plan_parser.load_plan()
ROOT = Path(__file__).resolve().parents[1].parent

START = """\
# Progress

## Phase 0: Foundation

| ID | Title | Pts | Status | PR | Notes |
|---|---|---|---|---|---|
| KS-001 | Repo scaffold and toolchain | 3 | done | | hand-written note |

## Found

Nothing yet.
"""


@pytest.mark.phase(0)
def test_adds_only_the_missing_rows_and_keeps_existing_ones() -> None:
    text, added = progress_sync.sync(START, PLAN)

    assert len(added) == 78 and "KS-001" not in added
    assert "| KS-001 | Repo scaffold and toolchain | 3 | done | | hand-written note |" in text
    assert "| KS-908 | Release v1.0.0 | 2 | todo | | |" in text
    for number in range(10):
        assert f"## Phase {number}: " in text
    assert text.index("## Phase 0:") < text.index("## Phase 9:") < text.index("## Found")
    assert text.count("| KS-") == 79


@pytest.mark.phase(0)
def test_rows_land_inside_their_phase_table_in_story_order() -> None:
    text, _ = progress_sync.sync(START, PLAN)

    phase_zero = text.split("## Phase 1:")[0]
    ids = [
        line.split("|")[1].strip() for line in phase_zero.splitlines() if line.startswith("| KS-")
    ]
    assert ids == [f"KS-00{n}" for n in range(1, 8)]


@pytest.mark.phase(0)
def test_second_sync_changes_nothing() -> None:
    once, _ = progress_sync.sync(START, PLAN)
    twice, added = progress_sync.sync(once, PLAN)

    assert added == []
    assert twice == once


@pytest.mark.phase(0)
def test_check_mode_reports_without_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    progress = tmp_path / "progress.md"
    progress.write_text(START)

    assert progress_sync.main(["--check", "--file", str(progress)]) == 1
    assert progress.read_text() == START
    assert "78 stories are missing" in capsys.readouterr().out

    assert progress_sync.main(["--file", str(progress)]) == 0
    assert progress_sync.main(["--check", "--file", str(progress)]) == 0


@pytest.mark.phase(0)
def test_the_committed_progress_file_lists_every_story() -> None:
    text = (ROOT / "docs" / "progress.md").read_text()

    _, added = progress_sync.sync(text, PLAN)

    assert added == []
