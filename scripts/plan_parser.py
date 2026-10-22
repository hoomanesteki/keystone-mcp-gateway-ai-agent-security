"""Parse docs/PLAN.md into phases, stories, epics and themes.

The other backlog scripts share this module, so the plan's format is read in one place.
A story block starts at `#### KS-xxx · Title` and ends at the next heading or a `---` line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "docs" / "PLAN.md"

STORY_HEADING = re.compile(r"^#### (KS-\d{3}) · (.+)$")
PHASE_HEADING = re.compile(r"^## Phase (\d+): (.+?)(?: \(tag (v\d+\.\d+\.\d+)\))?$")
TRACKING_LINE = re.compile(
    r"^- \*\*Epic:\*\* (E\d+) · \*\*Points:\*\* (\d+) · \*\*Branch:\*\* `([^`]+)`"
    r" · \*\*Depends on:\*\* (.+)$"
)
TESTS_LINE = re.compile(r"^- \*\*Tests:\*\* (.*)$")
BACKTICKED = re.compile(r"`([^`]+)`")


@dataclass(frozen=True)
class Story:
    id: str
    title: str
    phase: int
    epic: str
    points: int
    branch: str
    depends_on: tuple[str, ...]
    tests: tuple[str, ...]
    block: str

    @property
    def body(self) -> str:
        """The block without its heading, which the issue title already carries."""
        return "\n".join(self.block.splitlines()[1:]).strip() + "\n"


@dataclass(frozen=True)
class Epic:
    id: str
    name: str
    theme: str
    points: int


@dataclass(frozen=True)
class Phase:
    number: int
    name: str
    tag: str
    stories: tuple[Story, ...]

    @property
    def points(self) -> int:
        return sum(story.points for story in self.stories)


@dataclass(frozen=True)
class Plan:
    phases: tuple[Phase, ...]
    epics: tuple[Epic, ...]
    themes: dict[str, str]

    @property
    def stories(self) -> tuple[Story, ...]:
        return tuple(story for phase in self.phases for story in phase.stories)

    @property
    def points(self) -> int:
        return sum(phase.points for phase in self.phases)

    def epic(self, epic_id: str) -> Epic:
        return next(epic for epic in self.epics if epic.id == epic_id)


def _table_rows(lines: list[str], heading: str) -> list[list[str]]:
    """Cells of each data row in the first table under the `### <heading>` section."""
    start = next((i for i, line in enumerate(lines) if line.startswith(f"### {heading}")), None)
    if start is None:
        return []
    rows: list[list[str]] = []
    for line in lines[start + 1 :]:
        if line.startswith(("### ", "## ")):
            break
        if line.startswith("|"):
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            rows.append(cells)
    return [row for row in rows[2:] if row[0]]  # drop the header and the separator


def _parse_story(heading: re.Match[str], block_lines: list[str], phase: int) -> Story:
    tracking = next((m for m in map(TRACKING_LINE.match, block_lines) if m), None)
    if tracking is None:
        raise ValueError(f"{heading[1]}: no 'Epic, Points, Branch, Depends on' line")
    epic, points, branch, depends = tracking.groups()
    tests: tuple[str, ...] = ()
    for line in block_lines:
        found = TESTS_LINE.match(line)
        if found:
            tests = tuple(item for item in BACKTICKED.findall(found[1]) if "::" in item)
            break
    depends_on = () if depends.strip().lower() == "none" else tuple(depends.split(", "))
    block = "\n".join(block_lines).rstrip() + "\n"
    return Story(
        id=heading[1],
        title=heading[2].strip(),
        phase=phase,
        epic=epic,
        points=int(points),
        branch=branch,
        depends_on=depends_on,
        tests=tests,
        block=block,
    )


def parse_plan(text: str) -> Plan:
    lines = text.splitlines()
    phases: list[tuple[int, str, str, list[Story]]] = []
    current = -1
    i = 0
    while i < len(lines):
        phase_match = PHASE_HEADING.match(lines[i])
        story_match = STORY_HEADING.match(lines[i])
        if phase_match:
            number, name, tag = int(phase_match[1]), phase_match[2], phase_match[3] or ""
            phases.append((number, name, tag, []))
            current = len(phases) - 1
        elif story_match:
            if current < 0:
                raise ValueError(f"{story_match[1]} appears before any phase heading")
            end = i + 1
            while end < len(lines) and not (
                lines[end].startswith(("#### ", "### ", "## ")) or lines[end].strip() == "---"
            ):
                end += 1
            phases[current][3].append(_parse_story(story_match, lines[i:end], phases[current][0]))
            i = end - 1
        i += 1

    epics = tuple(
        Epic(row[0], row[1], row[2], int(row[4]))
        for row in _table_rows(lines, "6.2")
        if re.fullmatch(r"E\d+", row[0])
    )
    themes = {row[0]: row[1] for row in _table_rows(lines, "6.1")}
    return Plan(
        phases=tuple(Phase(n, name, tag, tuple(stories)) for n, name, tag, stories in phases),
        epics=epics,
        themes=themes,
    )


def load_plan(path: Path | None = None) -> Plan:
    return parse_plan((path or PLAN_PATH).read_text(encoding="utf-8"))
