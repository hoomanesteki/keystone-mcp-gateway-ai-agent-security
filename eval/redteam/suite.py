"""Read the scenarios of the red-team suite from `eval/redteam/scenarios/` (KS-901).

    for scenario in load_scenarios(): ...

The files are written by `python -m eval.redteam.build` and are committed, so a result of a run can
name a scenario and a reader can open the file it came from.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import yaml

from eval.redteam.schema import Scenario

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SCENARIOS = HERE / "scenarios"
VARIANTS = REPO / "examples" / "fixtures" / "variants"


def load_scenarios(folder: Path | None = None) -> list[Scenario]:
    """Every scenario of the folder, in the order of the files and of the entries in them."""
    found: list[Scenario] = []
    for path in sorted((folder or SCENARIOS).glob("*.yaml")):
        entries = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(entries, list):
            raise ValueError(f"{path.name}: expected a list of scenarios")
        found += [Scenario.model_validate(entry) for entry in entries]
    return found


def by_id(scenarios: Sequence[Scenario]) -> dict[str, Scenario]:
    found = {s.id: s for s in scenarios}
    if len(found) != len(scenarios):
        raise ValueError("two scenarios have the same id")
    return found
