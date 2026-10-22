import json
from collections.abc import Sequence
from typing import Any

import import_backlog
import plan_parser
import pytest

PLAN = plan_parser.load_plan()
REPO = "octo/keystone"


class FakeGh:
    """An in-memory GitHub that understands the few `gh` commands the importer uses."""

    def __init__(self, signed_in: bool = True) -> None:
        self.signed_in = signed_in
        self.labels: set[str] = set()
        self.milestones: dict[str, int] = {}
        self.issues: list[dict[str, Any]] = []
        self.calls: list[list[str]] = []

    def __call__(self, args: Sequence[str], stdin: str | None) -> str:
        a = list(args)
        self.calls.append(a)
        if a[:2] == ["auth", "status"]:
            if not self.signed_in:
                raise RuntimeError("not signed in")
            return ""
        if a[:2] == ["label", "list"]:
            return json.dumps([{"name": name} for name in sorted(self.labels)])
        if a[:2] == ["label", "create"]:
            self.labels.add(a[2])
            return ""
        if a[0] == "api" and "milestones" in a[1]:
            if "-f" not in a:
                return json.dumps([{"title": t, "number": n} for t, n in self.milestones.items()])
            title = next(x for x in a if x.startswith("title="))[6:]
            self.milestones[title] = len(self.milestones) + 1
            return "{}"
        if a[:2] == ["issue", "list"]:
            return json.dumps(self.issues)
        if a[:2] == ["issue", "create"]:
            self.issues.append(
                {
                    "number": len(self.issues) + 1,
                    "title": self._value(a, "--title"),
                    "body": stdin,
                    "labels": [{"name": x} for x in self._values(a, "--label")],
                    "milestone": {"title": self._value(a, "--milestone")},
                }
            )
            return ""
        if a[:2] == ["issue", "edit"]:
            issue = next(i for i in self.issues if i["number"] == int(a[2]))
            names = {x["name"] for x in issue["labels"]}
            names |= set(self._values(a, "--add-label"))
            names -= set(self._values(a, "--remove-label"))
            issue.update(
                title=self._value(a, "--title"),
                body=stdin,
                labels=[{"name": x} for x in sorted(names)],
                milestone={"title": self._value(a, "--milestone")},
            )
            return ""
        raise AssertionError(f"unexpected gh call: {a}")

    @staticmethod
    def _values(args: list[str], flag: str) -> list[str]:
        return [args[i + 1] for i, x in enumerate(args) if x == flag]

    def _value(self, args: list[str], flag: str) -> str:
        return self._values(args, flag)[0]


def run(argv: list[str], gh: FakeGh) -> int:
    return import_backlog.main([*argv, "--repo", REPO], runner=gh, sleep=lambda _: None)


@pytest.mark.phase(0)
def test_dry_run_lists_every_story_without_calling_gh(capsys: pytest.CaptureFixture[str]) -> None:
    def forbidden(args: Sequence[str], stdin: str | None) -> str:
        raise AssertionError("dry run must not call gh")

    assert import_backlog.main(["--dry-run"], runner=forbidden) == 0

    out = capsys.readouterr().out
    assert "79 stories, 10 phases, 301 points" in out
    assert "KS-001" in out and "KS-908" in out
    assert out.count("\nPhase ") == 9 and out.startswith("Phase 0:")


@pytest.mark.phase(0)
def test_dry_run_can_be_limited_to_one_phase(capsys: pytest.CaptureFixture[str]) -> None:
    assert import_backlog.main(["--dry-run", "--phase", "3"]) == 0

    out = capsys.readouterr().out
    assert "8 stories, 1 phases, 28 points" in out
    assert "KS-301" in out and "KS-401" not in out


@pytest.mark.phase(0)
def test_second_run_creates_nothing() -> None:
    gh = FakeGh()

    assert run([], gh) == 0
    assert len(gh.issues) == 79
    assert len(gh.milestones) == 10
    created_calls = [c for c in gh.calls if c[:2] == ["issue", "create"]]
    assert len(created_calls) == 79

    gh.calls.clear()
    assert run([], gh) == 0
    assert len(gh.issues) == 79
    assert [c for c in gh.calls if c[:2] in (["issue", "create"], ["issue", "edit"])] == []
    assert [
        c for c in gh.calls if c[:2] == ["label", "create"] or (c[0] == "api" and "-f" in c)
    ] == []


@pytest.mark.phase(0)
def test_issue_has_id_title_story_body_labels_and_milestone() -> None:
    gh = FakeGh()
    run(["--phase", "0"], gh)

    issue = next(i for i in gh.issues if i["title"].startswith("KS-003 "))
    assert issue["title"] == "KS-003 CI pipeline and branch protection"
    assert issue["body"].startswith("- **Epic:** E01")
    assert "#### KS-003" not in issue["body"]
    assert {x["name"] for x in issue["labels"]} == {
        "phase:0", "theme:T5", "epic:E01", "pts:3", "type:story"
    }  # fmt: skip
    assert issue["milestone"] == {"title": "Phase 0"}
    assert len(gh.issues) == 7 and list(gh.milestones) == ["Phase 0"]


@pytest.mark.phase(0)
def test_changed_story_updates_the_issue_and_swaps_managed_labels() -> None:
    gh = FakeGh()
    run(["--phase", "0"], gh)
    stale = next(i for i in gh.issues if i["title"].startswith("KS-002 "))
    stale["body"] = "old text"
    stale["labels"] = [{"name": "pts:8"}, {"name": "phase:0"}, {"name": "needs-design"}]

    gh.calls.clear()
    run(["--phase", "0"], gh)

    edits = [c for c in gh.calls if c[:2] == ["issue", "edit"]]
    assert len(edits) == 1
    names = {x["name"] for x in stale["labels"]}
    assert "pts:8" not in names and "pts:3" in names
    assert "needs-design" in names, "labels outside the managed families are left alone"
    assert stale["body"].startswith("- **Epic:** E01")


@pytest.mark.phase(0)
def test_not_signed_in_exits_one_before_changing_anything(
    capsys: pytest.CaptureFixture[str],
) -> None:
    gh = FakeGh(signed_in=False)

    assert run([], gh) == 1
    assert gh.calls == [["auth", "status"]]
    assert "gh auth login" in capsys.readouterr().err
