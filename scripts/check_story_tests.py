#!/usr/bin/env python3
"""Check that every test named in the plan exists, for the stories up to a phase.

    check_story_tests.py --phase N [--plan PATH] [--root DIR]

Each `file::function` in a story's Tests line must be a function defined in that file, found by
parsing it with `ast` (nothing is imported or run). A Tests line that reads `none (...)` names
nothing. In a `.ts` or `.tsx` file the name is a test title: the file must contain
`test("<title>"` or `it("<title>"`, in single, double or backtick quotes. A `test.skip(` or
`test.only(` does not count, because a skipped test checks nothing and `only` switches the others
off. Exits 1 if any are missing.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from plan_parser import ROOT, Plan, load_plan

TYPESCRIPT_SUFFIXES = (".ts", ".tsx")
# `test(` or `it(` that is not a method call or part of a longer name, then a string literal.
TS_TEST = re.compile(
    r"""(?<![\w.$])(?:test|it)\s*\(\s*(?P<quote>["'`])(?P<title>(?:\\.|(?!(?P=quote)).)*)(?P=quote)""",
    re.DOTALL,
)


@dataclass(frozen=True)
class Missing:
    story: str
    test: str
    reason: str


@dataclass(frozen=True)
class Result:
    checked: int
    stories: int
    typescript: int
    missing: tuple[Missing, ...]


def defined_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def declared_tests(path: Path) -> set[str]:
    """The titles of the tests a TypeScript file declares."""
    text = path.read_text(encoding="utf-8")
    return {re.sub(r"\\(.)", r"\1", match["title"]) for match in TS_TEST.finditer(text)}


def check(plan: Plan, max_phase: int, root: Path) -> Result:
    cache: dict[Path, set[str] | None] = {}
    missing: list[Missing] = []
    checked = typescript = stories = 0
    for story in plan.stories:
        if story.phase > max_phase:
            continue
        stories += 1
        for test in story.tests:
            relative, _, name = test.rpartition("::")
            is_typescript = relative.endswith(TYPESCRIPT_SUFFIXES)
            checked += 1
            typescript += is_typescript
            path = root / relative.split("::")[0]
            if path not in cache:
                try:
                    if not path.is_file():
                        cache[path] = None
                    else:
                        cache[path] = (
                            declared_tests(path) if is_typescript else defined_functions(path)
                        )
                except SyntaxError:
                    cache[path] = set()
            names = cache[path]
            if names is None:
                missing.append(Missing(story.id, test, "file not found"))
            elif name not in names:
                missing.append(
                    Missing(
                        story.id, test, "test not found" if is_typescript else "function not found"
                    )
                )
    return Result(checked, stories, typescript, tuple(missing))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--phase", type=int, required=True, help="check phases 0 to N")
    parser.add_argument("--plan", type=Path, default=None)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)

    result = check(load_plan(args.plan), args.phase, args.root)
    for item in result.missing:
        print(f"{item.story}  {item.test}  ({item.reason})")
    print(
        f"{result.checked} tests checked across {result.stories} stories "
        f"({result.typescript} TypeScript), {len(result.missing)} missing"
    )
    return 1 if result.missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
