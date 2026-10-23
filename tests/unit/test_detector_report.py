"""KS-707: the report writes the numbers it measured, with their date and commit, and nothing else.

The document is made from a small run with a fake classifier, so no model is loaded. What is
checked is the shape: every table has a row for each config, a cell with nothing to say reads
"not measured", the markers of `docs/results.md` are kept, and the text follows the voice rules.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from eval.detector import report, run
from eval.detector.datasets import build
from eval.detector.report import (
    END,
    NOT,
    START,
    count_test_runs,
    num,
    rate,
    recall_cell,
    render_section,
    update_results,
)
from keystone.defense.classifier import FakeClassifier

pytestmark = pytest.mark.phase(7)


@pytest.fixture
def document(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(
        run,
        "load_classifier",
        lambda cfg: FakeClassifier(
            lambda t: 0.9 if "instruction" in t.lower() else 0.1, name="fake"
        ),
    )
    data = build(download=False)
    result = run.run_split(data, "dev", ("rules", "classifier", "combined"), limit=80)
    return {
        "date": "2026-10-23",
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "dirty": False,
        "machine": {"platform": "TestOS 1.0", "cpus": 4, "python": "3.12.0"},
        "model": {"id": report.MODEL, "revision": report.MODEL_REVISION, "classifier": "fake"},
        "dataset": report.dataset_facts(data),
        "test_runs": 2,
        "result": result,
    }


def test_the_section_has_a_table_for_each_thing_the_story_asks_for(
    document: dict[str, Any],
) -> None:
    section = render_section(document)

    assert section.startswith("## Detector")
    for heading in (
        "### How good the scores are",
        "### At the configured thresholds",
        "### False positives on hard negatives, on their own",
        "### Public prompts and documents apart",
        "### Time of a scan",
        "### With the 300 ms wait of the gateway",
        "### What is and is not in these numbers",
    ):
        assert heading in section, heading
    for name in ("Rules", "Model", "Rules and model"):
        assert f"| {name} |" in section
    assert "Recall at a false positive rate of 5% or less" in section
    # The date, the commit and the machine are stated.
    assert "Measured on 2026-10-23 at commit `0123456789ab`" in section
    assert "TestOS 1.0 (4 CPUs, Python 3.12.0)" in section
    assert "eval/results/detector-2026-10-23.json" in section
    assert "scored 2 time(s) before this report" in section


def test_a_dirty_tree_is_said_and_a_missing_part_is_said(document: dict[str, Any]) -> None:
    document["dirty"] = True

    section = render_section(document)

    assert "`0123456789ab plus uncommitted changes`" in section
    assert "**Not complete**: built offline" in section  # the made-up run had no public parts


def test_nothing_is_filled_in_where_nothing_was_measured(document: dict[str, Any]) -> None:
    for name in ("rules", "classifier", "combined"):
        latency = document["result"]["configs"][name]["latency"]
        latency["over 2000"] = {"n": 0, "p50_ms": None, "p95_ms": None}
        document["result"]["configs"][name]["roc_auc"] = None

    section = render_section(document)

    assert NOT in section
    assert "None" not in section and "nan" not in section.lower()


def test_the_text_follows_the_voice_rules(document: dict[str, Any]) -> None:
    import lint_prose

    section = render_section(document)

    assert "\u2014" not in section
    for label, pattern in lint_prose.BANNED_RE:
        assert not pattern.search(section), label
    assert "!" not in section


def test_cells_say_how_many_texts_a_rate_rests_on() -> None:
    cell = {"count": 24, "of": 84, "rate": 24 / 84, "ci95": [0.2001, 0.39]}

    assert rate(cell) == "0.29 (24 of 84, 95% 0.20 to 0.39)"
    assert rate(None) == NOT and rate({"rate": None}) == NOT
    assert num(None) == NOT and num(0.5) == "0.50" and num(0.123, 3) == "0.123"
    point = {"recall": 0.9, "recall_ci95": [0.8, 0.95], "threshold": 0.4, "fpr": 0.05}
    assert recall_cell(point) == "0.90 (95% 0.80 to 0.95) at 0.40"
    assert recall_cell(None) == NOT


# -- docs/results.md


def test_the_document_is_made_when_it_is_missing(tmp_path: Path) -> None:
    path = tmp_path / "results.md"

    update_results(path, "## Detector\n\nnumbers\n")

    text = path.read_text()
    assert text.startswith("# Results") and START in text and END in text
    assert "## Detector\n\nnumbers" in text


def test_the_section_is_replaced_between_the_markers_and_the_rest_is_kept(tmp_path: Path) -> None:
    path = tmp_path / "results.md"
    path.write_text(f"# Results\n\nintro\n\n{START}\nold\n{END}\n\n## Other\n\nkept\n")

    update_results(path, "## Detector\n\nnew\n")
    update_results(path, "## Detector\n\nnewer\n")

    text = path.read_text()
    assert "old" not in text and "newer" in text and "\nnew\n" not in text
    assert text.count(START) == 1 and text.count(END) == 1
    assert "intro" in text and "## Other\n\nkept" in text


def test_the_test_runs_are_counted_from_the_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "runs.jsonl"
    monkeypatch.setattr(run, "RUN_LOG", log)
    assert count_test_runs() == 0

    log.write_text('{"a": 1}\n\n{"a": 2}\n')

    assert count_test_runs() == 2


def test_the_command_writes_the_json_and_the_section_and_logs_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: dict[str, Any]
) -> None:
    results = tmp_path / "results"
    doc = tmp_path / "results.md"
    monkeypatch.setattr(report, "RESULTS", results)
    monkeypatch.setattr(report, "RESULTS_DOC", doc)
    monkeypatch.setattr(run, "RUN_LOG", results / "test-runs.jsonl")
    monkeypatch.setattr(report, "build_document", lambda data, limit=None: document)

    status = report.main(["--offline"])

    assert status == 0
    written = json.loads((results / "detector-2026-10-23.json").read_text())
    assert written["commit"] == document["commit"] and "result" in written
    assert "## Detector" in doc.read_text()
    assert len((results / "test-runs.jsonl").read_text().splitlines()) == 1


def test_a_limited_run_prints_and_writes_no_report_but_is_logged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    log = tmp_path / "log" / "runs.jsonl"
    monkeypatch.setattr(report, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(report, "RESULTS_DOC", tmp_path / "results.md")
    monkeypatch.setattr(run, "RUN_LOG", log)
    monkeypatch.setattr(report, "build_document", lambda data, limit=None: document)

    report.main(["--offline", "--limit", "20"])

    assert "## Detector" in capsys.readouterr().out
    assert not (tmp_path / "results").exists() and not (tmp_path / "results.md").exists()
    # It read the test split, so it is on the record, with what it was.
    logged = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(logged) == 1 and logged[0]["note"] == "report with --limit 20"
