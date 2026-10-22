#!/usr/bin/env python3
"""Add a row to docs/progress.md for every plan story that is missing there.

    progress_sync.py [--check] [--file PATH] [--plan PATH]

Existing rows are never changed, so statuses and notes written by hand survive. A new row has
status `todo`. With --check nothing is written and the exit code is 1 if rows are missing.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from plan_parser import ROOT, Phase, Plan, Story, load_plan

PROGRESS_PATH = ROOT / "docs" / "progress.md"
HEADER = "| ID | Title | Pts | Status | PR | Notes |"
SEPARATOR = "|---|---|---|---|---|---|"
SECTION = re.compile(r"^## Phase (\d+):")


def row(story: Story) -> str:
    title = story.title.replace("|", "\\|")
    return f"| {story.id} | {title} | {story.points} | todo | | |"


def section_text(phase: Phase) -> list[str]:
    return [f"## Phase {phase.number}: {phase.name}", "", HEADER, SEPARATOR]


def find_section(lines: list[str], number: int) -> int | None:
    for index, line in enumerate(lines):
        match = SECTION.match(line)
        if match and int(match[1]) == number:
            return index
    return None


def section_end(lines: list[str], start: int) -> int:
    return next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))


def sync(text: str, plan: Plan) -> tuple[str, list[str]]:
    """Return the new text and the ids of the rows that were added."""
    lines = text.splitlines()
    added: list[str] = []
    for phase in plan.phases:
        start = find_section(lines, phase.number)
        if start is None:
            start = next((i for i, line in enumerate(lines) if line == "## Found"), len(lines))
            lines[start:start] = [*section_text(phase), ""]
        end = section_end(lines, start)
        listed = (re.match(r"^\| (KS-\d{3}) \|", line) for line in lines[start:end])
        present = {match[1] for match in listed if match}
        missing = [story for story in phase.stories if story.id not in present]
        if not missing:
            continue
        table = [i for i in range(start, end) if lines[i].startswith("|")]
        if table:
            at = table[-1] + 1
        else:  # a section with no table yet
            lines[start + 1 : start + 1] = ["", HEADER, SEPARATOR]
            at = start + 4
        lines[at:at] = [row(story) for story in missing]
        added += [story.id for story in missing]
    return "\n".join(lines) + "\n", added


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--file", type=Path, default=PROGRESS_PATH)
    parser.add_argument("--plan", type=Path, default=None)
    args = parser.parse_args(argv)

    plan = load_plan(args.plan)
    new_text, added = sync(args.file.read_text(encoding="utf-8"), plan)
    if args.check:
        if added:
            print(f"{len(added)} stories are missing from {args.file}: {', '.join(added)}")
            return 1
        print("progress.md lists every story")
        return 0
    if added:
        args.file.write_text(new_text, encoding="utf-8")
    print(f"added {len(added)} rows")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
