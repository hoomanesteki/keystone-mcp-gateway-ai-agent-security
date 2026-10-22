import re
from pathlib import Path

import plan_parser
import pytest

PLAN_FILE = Path(__file__).resolve().parents[2] / "docs" / "PLAN.md"
PLAN = plan_parser.load_plan(PLAN_FILE)

SAMPLE = """\
## Phase 0: First (tag v0.0.1)

#### KS-001 · A first story
- **Epic:** E01 · **Points:** 3 · **Branch:** `chore/ks-001-first` · **Depends on:** none
- **Tests:** `tests/unit/test_a.py::test_one`, `tests/unit/test_a.py::test_two`

---

## Phase 1: Second (tag v0.1.0)

#### KS-101 · A second story
- **Epic:** E02 · **Points:** 5 · **Branch:** `feat/ks-101-second` · **Depends on:** KS-001, KS-002
- **Tests:** none (release checklist)

### 6.2 Epics

| Epic | Name | Theme | Phases | Points |
|---|---|---|---|---|
| E01 | Repo | T5 | 0 | 3 |
"""


@pytest.mark.phase(0)
def test_parses_story_blocks() -> None:
    plan = plan_parser.parse_plan(SAMPLE)

    first, second = plan.stories
    assert (first.id, first.title, first.phase) == ("KS-001", "A first story", 0)
    assert (first.epic, first.points, first.branch) == ("E01", 3, "chore/ks-001-first")
    assert first.depends_on == ()
    assert first.tests == ("tests/unit/test_a.py::test_one", "tests/unit/test_a.py::test_two")
    assert first.block.startswith("#### KS-001")
    assert "---" not in first.block
    assert (second.phase, second.depends_on, second.tests) == (1, ("KS-001", "KS-002"), ())
    assert [(p.number, p.name, p.tag) for p in plan.phases] == [
        (0, "First", "v0.0.1"),
        (1, "Second", "v0.1.0"),
    ]

    real = next(s for s in PLAN.stories if s.id == "KS-001")
    assert real.title == "Repo scaffold and toolchain"
    assert real.branch == "chore/ks-001-scaffold"
    assert "tests/unit/test_package.py::test_version_exposed" in real.tests
    assert real.body.startswith("- **Epic:** E01")


@pytest.mark.phase(0)
def test_points_total_matches_plan() -> None:
    assert len(PLAN.stories) == 79
    assert [p.number for p in PLAN.phases] == list(range(10))
    assert PLAN.points == 301

    text = PLAN_FILE.read_text()
    summary = re.findall(r"^\| (\d) \| [^|]+ \| (\d+) \| (\d+) \| (v[\d.]+) \|", text, re.MULTILINE)
    assert len(summary) == 10
    for number, stories, points, tag in summary:
        phase = PLAN.phases[int(number)]
        assert (len(phase.stories), phase.points, phase.tag) == (int(stories), int(points), tag)


@pytest.mark.phase(0)
def test_epic_points_match_the_epic_table() -> None:
    by_epic: dict[str, int] = {}
    for story in PLAN.stories:
        by_epic[story.epic] = by_epic.get(story.epic, 0) + story.points

    assert {epic.id: epic.points for epic in PLAN.epics} == by_epic
    assert len(PLAN.epics) == 17
    assert set(PLAN.themes) == {f"T{n}" for n in range(1, 7)}


@pytest.mark.phase(0)
def test_plan_is_internally_consistent() -> None:
    ids = [story.id for story in PLAN.stories]
    assert len(set(ids)) == len(ids)
    assert len({story.branch for story in PLAN.stories}) == len(ids)
    for story in PLAN.stories:
        assert story.id[3:4] == str(story.phase), f"{story.id} sits in phase {story.phase}"
        assert set(story.depends_on) <= set(ids), f"{story.id} depends on an unknown story"
        assert story.id not in story.depends_on
        assert story.points in (1, 2, 3, 5, 8)
    # 251 named tests, one per `file::function` item in the Tests lines.
    assert sum(len(story.tests) for story in PLAN.stories) == 251
