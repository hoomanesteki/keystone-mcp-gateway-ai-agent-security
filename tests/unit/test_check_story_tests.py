from pathlib import Path

import check_story_tests
import plan_parser
import pytest

ROOT = Path(__file__).resolve().parents[2]


def story(story_id: str, title: str, tests: str, branch: str) -> str:
    return (
        f"#### {story_id} · {title}\n"
        f"- **Epic:** E01 · **Points:** 1 · **Branch:** `{branch}` · **Depends on:** none\n"
        f"- **Tests:** {tests}\n\n"
    )


PLAN = (
    "## Phase 0: First (tag v0.0.1)\n\n"
    + story(
        "KS-001",
        "Present",
        "`tests/unit/test_a.py::test_exists`, `tests/unit/test_a.py::test_in_class`, "
        "`tests/unit/test_a.py::test_async`",
        "chore/ks-001-present",
    )
    + story(
        "KS-002",
        "Missing",
        "`tests/unit/test_a.py::test_gone`, `tests/unit/test_nofile.py::test_x`, "
        "`console/src/a.test.tsx::renders a page`",
        "chore/ks-002-missing",
    )
    + story("KS-003", "None", "none (release checklist)", "chore/ks-003-none")
    + story(
        "KS-004",
        "Console",
        "`console/src/b.test.tsx::renders a page`, `console/src/b.test.tsx::single quoted`, "
        '`console/src/b.test.tsx::backtick quoted`, `console/src/b.test.tsx::says "hi"`, '
        "`console/src/b.test.tsx::it style`, `console/src/b.test.tsx::skipped one`, "
        "`console/src/b.test.tsx::focused one`, `console/src/b.test.tsx::not a test`, "
        "`console/src/b.test.tsx::never written`",
        "feat/ks-004-console",
    )
    + "## Phase 1: Later (tag v0.1.0)\n\n"
    + story("KS-101", "Later", "`tests/unit/test_later.py::test_not_yet`", "feat/ks-101-later")
)


@pytest.fixture
def project(tmp_path: Path) -> tuple[plan_parser.Plan, Path]:
    tests = tmp_path / "tests" / "unit"
    tests.mkdir(parents=True)
    (tests / "test_a.py").write_text(
        "def test_exists():\n    pass\n\n"
        "class TestGroup:\n    def test_in_class(self):\n        pass\n\n"
        "async def test_async():\n    pass\n"
    )
    console = tmp_path / "console" / "src"
    console.mkdir(parents=True)
    (console / "b.test.tsx").write_text(
        'import { it, test } from "vitest";\n\n'
        'test("renders a page", () => {});\n'
        "test('single quoted', () => {});\n"
        "test(`backtick quoted`, () => {});\n"
        'test("says \\"hi\\"", () => {});\n'
        'describe("group", () => {\n  it(\n    "it style",\n    () => {},\n  );\n});\n'
        'test.skip("skipped one", () => {});\n'
        'test.only("focused one", () => {});\n'
        'fakeApi.test("not a test");\n'
        'const attest = (name: string) => name;\nattest("not a test");\n'
    )
    return plan_parser.parse_plan(PLAN), tmp_path


@pytest.mark.phase(0)
def test_reports_missing_test(project: tuple[plan_parser.Plan, Path]) -> None:
    plan, root = project

    result = check_story_tests.check(plan, 0, root)

    assert {(m.story, m.test, m.reason) for m in result.missing} == {
        ("KS-002", "tests/unit/test_a.py::test_gone", "function not found"),
        ("KS-002", "tests/unit/test_nofile.py::test_x", "file not found"),
        ("KS-002", "console/src/a.test.tsx::renders a page", "file not found"),
        ("KS-004", "console/src/b.test.tsx::skipped one", "test not found"),
        ("KS-004", "console/src/b.test.tsx::focused one", "test not found"),
        ("KS-004", "console/src/b.test.tsx::not a test", "test not found"),
        ("KS-004", "console/src/b.test.tsx::never written", "test not found"),
    }
    assert result.checked == 15
    assert result.typescript == 10
    assert result.stories == 4


@pytest.mark.phase(0)
def test_stories_after_the_phase_are_not_checked(project: tuple[plan_parser.Plan, Path]) -> None:
    plan, root = project

    assert all(m.story != "KS-101" for m in check_story_tests.check(plan, 0, root).missing)
    assert any(m.story == "KS-101" for m in check_story_tests.check(plan, 1, root).missing)


@pytest.mark.phase(0)
def test_main_exit_codes_and_output(
    project: tuple[plan_parser.Plan, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, root = project
    plan_file = root / "PLAN.md"
    plan_file.write_text(PLAN)

    assert (
        check_story_tests.main(["--phase", "0", "--plan", str(plan_file), "--root", str(root)]) == 1
    )
    out = capsys.readouterr().out
    assert "KS-002  tests/unit/test_a.py::test_gone  (function not found)" in out
    assert "KS-004  console/src/b.test.tsx::never written  (test not found)" in out
    assert "15 tests checked across 4 stories (10 TypeScript), 7 missing" in out


@pytest.mark.phase(0)
def test_phase_zero_tests_all_exist_in_this_repository() -> None:
    result = check_story_tests.check(plan_parser.load_plan(), 0, ROOT)

    assert result.missing == ()
    assert result.checked >= 15


@pytest.mark.phase(6)
def test_typescript_tests_are_found_by_their_title(project: tuple[plan_parser.Plan, Path]) -> None:
    plan, root = project

    result = check_story_tests.check(plan, 0, root)

    found = {m.test for m in result.missing}
    for title in (
        "renders a page",
        "single quoted",
        "backtick quoted",
        'says "hi"',
        "it style",
    ):
        assert f"console/src/b.test.tsx::{title}" not in found


@pytest.mark.phase(6)
def test_a_skipped_or_focused_typescript_test_is_not_a_test(
    project: tuple[plan_parser.Plan, Path],
) -> None:
    """A skipped test checks nothing, and `only` switches every other test of the file off."""
    plan, root = project

    result = check_story_tests.check(plan, 0, root)

    found = {m.test for m in result.missing}
    assert "console/src/b.test.tsx::skipped one" in found
    assert "console/src/b.test.tsx::focused one" in found
    assert "console/src/b.test.tsx::not a test" in found


@pytest.mark.phase(6)
def test_every_test_the_plan_names_up_to_phase_six_exists_in_this_repository() -> None:
    result = check_story_tests.check(plan_parser.load_plan(), 6, ROOT)

    assert result.missing == ()
    # The console's tests: two for the scaffold, three each for the queue and the audit page, two
    # for the tools page and one in the browser.
    assert result.typescript >= 11
