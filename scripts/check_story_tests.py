#!/usr/bin/env python3
"""Check that every test named in the plan exists, for the stories up to a phase.

    check_story_tests.py --phase N [--plan PATH] [--root DIR]

Each `file::function` in a story's Tests line must be a function defined in that file, found by
parsing it with `ast` (nothing is imported or run). A Tests line that reads `none (...)` names
nothing. TypeScript tests are skipped until KS-605 adds the console. Exits 1 if any are missing.
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

from plan_parser import ROOT, Plan, load_plan

TYPESCRIPT_SUFFIXES = (".ts", ".tsx")


@dataclass(frozen=True)
class Missing:
    story: str
    test: str
    reason: str


@dataclass(frozen=True)
class Result:
    checked: int
    stories: int
    skipped_typescript: int
    missing: tuple[Missing, ...]


def defined_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def check(plan: Plan, max_phase: int, root: Path) -> Result:
    cache: dict[Path, set[str] | None] = {}
    missing: list[Missing] = []
    checked = skipped = stories = 0
    for story in plan.stories:
        if story.phase > max_phase:
            continue
        stories += 1
        for test in story.tests:
            relative, _, name = test.rpartition("::")
            if relative.endswith(TYPESCRIPT_SUFFIXES):
                skipped += 1
                continue
            checked += 1
            path = root / relative.split("::")[0]
            if path not in cache:
                try:
                    cache[path] = defined_functions(path) if path.is_file() else None
                except SyntaxError:
                    cache[path] = set()
            functions = cache[path]
            if functions is None:
                missing.append(Missing(story.id, test, "file not found"))
            elif name not in functions:
                missing.append(Missing(story.id, test, "function not found"))
    return Result(checked, stories, skipped, tuple(missing))


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
        f"{result.checked} tests checked across {result.stories} stories, "
        f"{result.skipped_typescript} TypeScript skipped, {len(result.missing)} missing"
    )
    return 1 if result.missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
