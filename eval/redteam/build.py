"""Write the scenarios and variants of the red-team suite, or check that they are as written.

    python -m eval.redteam.build            # write eval/redteam/scenarios/*.yaml and the variants
    python -m eval.redteam.build --check    # exit 1 when a file differs from what the catalog makes

The catalog (`catalog.py`) is the source (KS-901). Its output is committed, because a result names a
scenario and a variant, and what the agent was given should be readable without running anything.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from eval.redteam.catalog import Built, build, scenario_yaml
from eval.redteam.suite import SCENARIOS, VARIANTS


def expected_files(built: Built) -> dict[Path, str]:
    """Every file the catalog makes, by path."""
    files: dict[Path, str] = {}
    for task, scenarios in built.scenarios.items():
        files[SCENARIOS / f"{task}.yaml"] = scenario_yaml(scenarios)
    for variant, content in built.variants.items():
        for relative, text in content.items():
            files[VARIANTS / variant / relative] = text
    return files


def on_disk() -> set[Path]:
    found = {p for p in SCENARIOS.glob("*.yaml")}
    found |= {p for p in VARIANTS.rglob("*") if p.is_file()}
    return found


def differences(built: Built) -> list[str]:
    """What is wrong with the files on disk: a file missing, one that differs, one nobody makes."""
    wanted = expected_files(built)
    problems = []
    for path, text in sorted(wanted.items()):
        if not path.is_file():
            problems.append(f"missing: {path}")
        elif path.read_text(encoding="utf-8") != text:
            problems.append(f"differs: {path}")
    problems += [f"not made by the catalog: {p}" for p in sorted(on_disk() - wanted.keys())]
    return problems


def write(built: Built) -> int:
    """Write the files, after taking away the ones a former build made and this one does not."""
    wanted = expected_files(built)
    for stale in on_disk() - wanted.keys():
        stale.unlink()
    for folder in sorted({p.parent for p in VARIANTS.rglob("*") if p.is_dir()}, reverse=True):
        if not any(folder.iterdir()):
            shutil.rmtree(folder)
    for path, text in wanted.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return len(wanted)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the scenarios and variants of the suite")
    parser.add_argument("--check", action="store_true", help="only check the files on disk")
    args = parser.parse_args(argv)
    built = build()
    if args.check:
        problems = differences(built)
        for line in problems:
            print(line, file=sys.stderr)
        return 1 if problems else 0
    count = write(built)
    scenarios = sum(len(v) for v in built.scenarios.values())
    print(f"wrote {count} files: {scenarios} scenarios and {len(built.variants)} variants")
    return 0


if __name__ == "__main__":
    sys.exit(main())
