"""KS-906: every test the threat model points at exists, and the model covers the plan's rows."""

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOC = (ROOT / "docs" / "threat-model.md").read_text()
LINK = re.compile(r"`(tests/[\w/]+\.py)::(\w+)`")


def functions_of(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


@pytest.mark.phase(9)
def test_every_test_the_threat_model_links_exists() -> None:
    links = LINK.findall(DOC)
    assert len(links) >= 40
    missing = [
        f"{file}::{name}"
        for file, name in links
        if not (ROOT / file).is_file() or name not in functions_of(ROOT / file)
    ]
    assert missing == []


@pytest.mark.phase(9)
def test_every_stride_row_and_invariant_has_a_link() -> None:
    sections = {part.split("\n", 1)[0].strip(): part for part in DOC.split("\n## ")[1:]}
    for title in ("Threats (STRIDE)", "Invariants", "Input limits"):
        rows = [
            line
            for line in sections[title].splitlines()
            if line.startswith("| ")
            and not line.startswith(("| Threat", "| ID", "| Input", "|---"))
        ]
        assert len(rows) >= 8 or title == "Input limits"
        for row in rows:
            assert LINK.search(row), row
    for number in range(1, 9):
        assert f"| I{number} |" in DOC


@pytest.mark.phase(9)
def test_every_accepted_risk_gives_a_reason_and_names_a_way_out() -> None:
    section = DOC.split("## Accepted risks")[1].split("\n## ")[0]
    rows = [
        r
        for r in section.splitlines()
        if r.startswith("| ") and not r.startswith(("| Risk", "|---"))
    ]
    assert len(rows) >= 5
    for row in rows:
        assert all(cell.strip() for cell in row.strip("|").split("|")), row


@pytest.mark.phase(9)
def test_the_gaps_that_need_code_are_rows_of_the_progress_table() -> None:
    progress = (ROOT / "docs" / "progress.md").read_text()
    for story in sorted(
        set(re.findall(r"\| (KS-99\d) \|", DOC.split("## Gaps that need code")[1]))
    ):
        assert f"| {story} |" in progress
