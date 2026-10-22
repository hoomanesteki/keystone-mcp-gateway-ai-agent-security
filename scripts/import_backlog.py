#!/usr/bin/env python3
"""Create the plan's milestones, labels and one GitHub issue per story.

    import_backlog.py [--dry-run] [--phase N] [--repo OWNER/NAME]

Idempotent: an issue is matched by the story id at the start of its title (`KS-203 ...`), so a
second run creates nothing and only edits issues whose title, body, labels or milestone changed.
The GitHub CLI does the work, always with JSON output where it returns data. --dry-run touches
neither the network nor `gh`.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from plan_parser import Plan, Story, load_plan

Runner = Callable[[Sequence[str], str | None], str]

LABEL_FAMILIES = ("phase:", "theme:", "epic:", "pts:", "type:")
POINT_VALUES = (1, 2, 3, 5, 8)
ISSUE_TITLE_ID = re.compile(r"^(KS-\d{3})\b")
CREATE_PAUSE_SECONDS = 1.0  # GitHub throttles bursts of content creation


def run_gh(args: Sequence[str], stdin: str | None = None) -> str:
    result = subprocess.run(["gh", *args], input=stdin, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {result.stderr.strip()}")
    return result.stdout


@dataclass(frozen=True)
class Label:
    name: str
    color: str
    description: str


def story_type(story: Story) -> str:
    if story.title.lower().startswith("spike"):
        return "spike"
    prefix = story.branch.split("/")[0]
    return prefix if prefix in ("fix", "chore") else "story"


def wanted_labels(plan: Plan) -> list[Label]:
    labels = [
        Label(f"phase:{p.number}", "1d76db", f"Phase {p.number}: {p.name}") for p in plan.phases
    ]
    labels += [Label(f"theme:{t}", "5319e7", name) for t, name in plan.themes.items()]
    labels += [Label(f"epic:{e.id}", "0e8a16", e.name) for e in plan.epics]
    labels += [Label(f"pts:{n}", "fbca04", f"{n} story points") for n in POINT_VALUES]
    labels += [Label(f"type:{t}", "d93f0b", f"A {t}") for t in ("story", "spike", "fix", "chore")]
    return labels


def story_labels(plan: Plan, story: Story) -> list[str]:
    epic = plan.epic(story.epic)
    return [
        f"phase:{story.phase}",
        f"theme:{epic.theme}",
        f"epic:{story.epic}",
        f"pts:{story.points}",
        f"type:{story_type(story)}",
    ]


def issue_title(story: Story) -> str:
    return f"{story.id} {story.title}"


class Github:
    def __init__(self, repo: str, runner: Runner = run_gh) -> None:
        self.repo = repo
        self.runner = runner

    def _json(self, args: Sequence[str]) -> Any:
        return json.loads(self.runner(args, None) or "null")

    def labels(self) -> set[str]:
        rows = self._json(
            ["label", "list", "--repo", self.repo, "--limit", "500", "--json", "name"]
        )
        return {row["name"] for row in rows}

    def create_label(self, label: Label) -> None:
        self.runner(
            ["label", "create", label.name, "--repo", self.repo, "--color", label.color,
             "--description", label.description, "--force"],
            None,
        )  # fmt: skip

    def milestones(self) -> dict[str, int]:
        rows = self._json(["api", f"repos/{self.repo}/milestones?state=all&per_page=100"])
        return {row["title"]: row["number"] for row in rows}

    def create_milestone(self, title: str, description: str) -> None:
        self.runner(
            ["api", f"repos/{self.repo}/milestones", "-f", f"title={title}",
             "-f", f"description={description}"],
            None,
        )  # fmt: skip

    def issues(self) -> list[dict[str, Any]]:
        return self._json(
            ["issue", "list", "--repo", self.repo, "--state", "all", "--limit", "1000",
             "--json", "number,title,body,labels,milestone"]
        )  # fmt: skip

    def create_issue(self, title: str, body: str, labels: list[str], milestone: str) -> None:
        args = ["issue", "create", "--repo", self.repo, "--title", title, "--body-file", "-",
                "--milestone", milestone]  # fmt: skip
        for label in labels:
            args += ["--label", label]
        self.runner(args, body)

    def edit_issue(
        self, number: int, title: str, body: str, add: list[str], remove: list[str], milestone: str
    ) -> None:
        args = ["issue", "edit", str(number), "--repo", self.repo, "--title", title,
                "--body-file", "-", "--milestone", milestone]  # fmt: skip
        for label in add:
            args += ["--add-label", label]
        for label in remove:
            args += ["--remove-label", label]
        self.runner(args, body)


def selected(plan: Plan, phase: int | None) -> list[Story]:
    return [s for s in plan.stories if phase is None or s.phase == phase]


def dry_run(plan: Plan, phase: int | None, out: Callable[[str], None] = print) -> None:
    phases = [p for p in plan.phases if phase is None or p.number == phase]
    for item in phases:
        out(f"Phase {item.number}: {item.name} ({len(item.stories)} stories, {item.points} points)")
        for story in item.stories:
            out(
                f"  {story.id}  {story.title:<52}  {story.points} pts  {story.branch}"
                f"  [{' '.join(story_labels(plan, story))}]"
            )
    stories = selected(plan, phase)
    out(f"{len(stories)} stories, {len(phases)} phases, {sum(s.points for s in stories)} points")
    out(f"would create {len(phases)} milestones and {len(wanted_labels(plan))} labels, then issues")


def existing_by_id(issues: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for issue in issues:
        match = ISSUE_TITLE_ID.match(issue["title"])
        if match:
            found.setdefault(match[1], issue)
    return found


def apply(
    plan: Plan,
    gh: Github,
    phase: int | None,
    sleep: Callable[[float], None] = time.sleep,
    out: Callable[[str], None] = print,
) -> dict[str, int]:
    phases = [p for p in plan.phases if phase is None or p.number == phase]

    have_labels = gh.labels()
    for label in wanted_labels(plan):
        if label.name not in have_labels:
            gh.create_label(label)

    have_milestones = gh.milestones()
    for item in phases:
        title = f"Phase {item.number}"
        if title not in have_milestones:
            gh.create_milestone(title, f"{item.name} (tag {item.tag})")

    existing = existing_by_id(gh.issues())
    counts = {"created": 0, "updated": 0, "unchanged": 0}
    for story in selected(plan, phase):
        title, body = issue_title(story), story.body
        labels = story_labels(plan, story)
        milestone = f"Phase {story.phase}"
        issue = existing.get(story.id)
        if issue is None:
            gh.create_issue(title, body, labels, milestone)
            counts["created"] += 1
            out(f"created   {title}")
            sleep(CREATE_PAUSE_SECONDS)
            continue
        current = {label["name"] for label in issue["labels"]}
        managed = {name for name in current if name.startswith(LABEL_FAMILIES)}
        current_milestone = (issue.get("milestone") or {}).get("title")
        same = (
            issue["title"] == title
            and (issue.get("body") or "").strip() == body.strip()
            and managed == set(labels)
            and current_milestone == milestone
        )
        if same:
            counts["unchanged"] += 1
            continue
        gh.edit_issue(
            issue["number"], title, body,
            add=sorted(set(labels) - managed), remove=sorted(managed - set(labels)),
            milestone=milestone,
        )  # fmt: skip
        counts["updated"] += 1
        out(f"updated   {title}")
        sleep(CREATE_PAUSE_SECONDS)
    out(
        f"issues: {counts['created']} created, {counts['updated']} updated, "
        f"{counts['unchanged']} unchanged"
    )
    return counts


def repo_from_remote() -> str:
    url = subprocess.run(
        ["git", "remote", "get-url", "origin"], capture_output=True, text=True, check=True
    ).stdout.strip()
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$", url)
    if not match:
        raise SystemExit(f"cannot read owner/repo from the origin url: {url}")
    return match[1]


def main(
    argv: list[str],
    runner: Runner = run_gh,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="list what would be created")
    parser.add_argument("--phase", type=int, help="only this phase")
    parser.add_argument("--repo", help="OWNER/NAME, default: the origin remote")
    args = parser.parse_args(argv)

    plan = load_plan()
    if args.phase is not None and args.phase not in {p.number for p in plan.phases}:
        print(f"no phase {args.phase} in the plan", file=sys.stderr)
        return 2
    if args.dry_run:
        dry_run(plan, args.phase)
        return 0
    try:
        runner(["auth", "status"], None)
    except RuntimeError:
        print("gh is not signed in. Run 'gh auth login', then run this again.", file=sys.stderr)
        return 1
    apply(plan, Github(args.repo or repo_from_remote(), runner), args.phase, sleep)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
