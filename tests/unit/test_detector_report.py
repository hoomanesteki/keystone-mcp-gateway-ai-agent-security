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
    combination_record,
    combination_sections,
    count_test_runs,
    dataset_facts,
    describe_configs,
    earlier_runs,
    kinds_of_attack,
    limits,
    names_of,
    num,
    plural,
    rate,
    reading,
    recall_cell,
    render_section,
    run_passes,
    scored_before,
    skipped_note,
    small_groups,
    tuning_record,
    tuning_sentence,
    update_results,
)
from keystone.defense.classifier import FakeClassifier
from keystone.settings import ScannerSettings

pytestmark = pytest.mark.phase(7)

ROOT = Path(__file__).resolve().parents[2]


def row(shape: str, name: str, recall: float, **params: float) -> dict[str, Any]:
    return {
        "shape": shape,
        "aggregate": "max",
        "combiner": {"name": name, "params": params},
        "recall_at_fpr_5pct": recall,
    }


def share(rules: float, **by_shape: float) -> dict[str, Any]:
    return {
        "n": 100,
        "rules_at_0.5": rules,
        "model": {key: {"at_0.5": value, "at_0.95": value} for key, value in by_shape.items()},
    }


# What the sweep on dev leaves, made up: two shapes, and the join that was chosen.
COMBINATION = {
    "file": "combination-dev-2026-10-24.json",
    "n": 919,
    "injections": 463,
    "candidates": 320,
    "chosen": row("128/64", "rules_first", 0.67, floor=0.5, weight=0.7),
    "rows": [
        row("510/64", "rules", 0.52),
        row("510/64", "model", 0.16),
        row("510/64", "max", 0.16),
        row("510/64", "rules_first", 0.55, floor=0.5, weight=0.7),
        row("128/64", "rules", 0.52),
        row("128/64", "model", 0.25),
        row("128/64", "max", 0.25),
        row("128/64", "rules_first", 0.67, floor=0.5, weight=0.7),
    ],
    "diagnosis": {
        "documents with an attack": share(0.78, **{"510/64": 0.36, "128/64": 0.64}),
        "harmless documents": share(0.0, **{"510/64": 0.09, "128/64": 0.09}),
    },
    "bootstrap": {
        "resamples": 200,
        "gain_over_reference": {
            "chosen": {"mean": 0.15, "low": 0.1, "high": 0.2},
            "phase 7": {"mean": -0.36, "low": -0.4, "high": -0.3},
        },
    },
}


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
    result = run_passes(data, "dev", ScannerSettings(), limit=80)
    return {
        "date": "2026-10-23",
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "dirty": False,
        "machine": {"platform": "TestOS 1.0", "cpus": 4, "python": "3.12.0"},
        "model": {"id": report.MODEL, "revision": report.MODEL_REVISION, "classifier": "fake"},
        "dataset": report.dataset_facts(data),
        "test_runs": 2,
        "combination": COMBINATION,
        "result": result,
    }


def test_the_section_has_a_table_for_each_thing_the_story_asks_for(
    document: dict[str, Any],
) -> None:
    section = render_section(document)

    assert section.startswith("## Detector")
    for heading in (
        "### How the join and the windows were picked, on the dev split",
        "### How good the scores are",
        "### At the configured thresholds",
        "### False positives on hard negatives, on their own",
        "### Public prompts and documents apart",
        "### Time of a scan",
        "### With the 300 ms wait of the gateway",
        "### What is and is not in these numbers",
    ):
        assert heading in section, heading
    for name in (
        "Rules",
        "Model, windows of 128",
        "Model, windows of 510 (Phase 7)",
        "Higher of the two, windows of 510 (Phase 7)",
        "Rules first, then the model",
    ):
        assert f"| {name} |" in section, name
    assert "Recall at a false positive rate of 5% or less" in section
    # The date, the commit and the machine are stated.
    assert "Measured on 2026-10-23 at commit `0123456789ab`" in section
    assert "TestOS 1.0 (4 CPUs, Python 3.12.0)" in section
    assert "eval/results/detector-2026-10-23.json" in section
    assert "scored 2 times before this report" in section


def test_a_dirty_tree_is_said_and_a_missing_part_is_said(document: dict[str, Any]) -> None:
    document["dirty"] = True

    section = render_section(document)

    assert "`0123456789ab plus uncommitted changes`" in section
    assert "**Not complete**: built offline" in section  # the made-up run had no public parts


def test_nothing_is_filled_in_where_nothing_was_measured(document: dict[str, Any]) -> None:
    for name in ("rules", "classifier", "combined", "previous_classifier", "previous_combined"):
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

    report.main(["--offline", "--limit", "20", "--note", "a look at the shape"])

    assert "## Detector" in capsys.readouterr().out
    assert not (tmp_path / "results").exists() and not (tmp_path / "results.md").exists()
    # It read the test split, so it is on the record, with what it was.
    logged = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(logged) == 1
    assert logged[0]["note"] == "report with --limit 20; a look at the shape"


# -- what the text says about the thresholds, the earlier looks and the rows that pull apart

TUNING = {
    "file": "tuning-2026-10-23-combined.json",
    "n": 919,
    "recommended": {"suspicious": 0.5, "injection": None, "precision_floor": 0.95},
    "precision_floor": 0.95,
}


def test_the_thresholds_are_said_to_be_checked_on_dev_and_what_that_found() -> None:
    sentence = tuning_sentence(TUNING, 0.5, 0.85)

    assert "flagged at 0.5 and a session is tainted at 0.85" in sentence
    assert "919 texts, `eval/results/tuning-2026-10-23-combined.json`" in sentence
    assert "the best F0.5 of the combined score was at 0.5" in sentence
    assert "no threshold reached a precision of 0.95 for tainting, so they stayed." in sentence


def test_a_sweep_that_disagrees_with_the_thresholds_is_said_and_the_thresholds_stay() -> None:
    wanted = {
        **TUNING,
        "recommended": {"suspicious": 0.4, "injection": 0.8, "precision_floor": 0.95},
    }

    sentence = tuning_sentence(wanted, 0.5, 0.85)

    assert "was at 0.4, not 0.5" in sentence
    assert "for tainting was 0.8, not 0.85" in sentence
    assert sentence.endswith("and this report uses the configured ones.")


def test_a_sweep_that_agrees_on_both_thresholds_says_so() -> None:
    agreeing = {
        **TUNING,
        "recommended": {"suspicious": 0.5, "injection": 0.85, "precision_floor": 0.95},
    }

    sentence = tuning_sentence(agreeing, 0.5, 0.85)

    assert "0.85 was the lowest threshold with a precision of 0.95 for tainting" in sentence
    assert sentence.endswith("so they stayed.")


def test_without_a_tuning_record_nothing_is_claimed_about_one() -> None:
    sentence = tuning_sentence(None, 0.5, 0.85)

    assert "No tuning record is kept" in sentence and "checked on the dev split" not in sentence


def test_the_record_of_the_sweep_is_the_latest_one_for_the_combined_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(report, "RESULTS", tmp_path)
    assert tuning_record() is None
    for date, best in (("2026-10-22", 0.45), ("2026-10-23", 0.5)):
        body = {
            "date": date,
            "n": 919,
            "recommended": {"suspicious": best, "injection": None, "precision_floor": 0.95},
            "current": {"suspicious": 0.5, "injection": 0.85},
        }
        (tmp_path / f"tuning-{date}-combined.json").write_text(json.dumps(body))
    (tmp_path / "tuning-2026-10-24-rules.json").write_text("{}")  # not the combined score

    found = tuning_record()

    assert found is not None
    assert found["file"] == "tuning-2026-10-23-combined.json"
    assert found["recommended"]["suspicious"] == 0.5 and found["n"] == 919


def test_earlier_looks_at_the_test_split_are_listed_with_what_they_were() -> None:
    document = {
        "test_runs": 2,
        "earlier_runs": [
            {
                "at": "2026-10-23T17:55:36+00:00",
                "commit": "755e0cd4cacff21945ce88f84911bfa56e2acdb6",
                "dirty": True,
                "n": 200,
                "configs": ["rules"],
                "note": "a trial of the nightly command",
            },
            {
                "at": "2026-10-23T20:12:00+00:00",
                "commit": "d5d61cde64a493eecd241d0a01457dad09fa758b",
                "dirty": False,
                "n": 973,
                "configs": ["classifier", "combined", "combined_300ms", "rules"],
            },
        ],
    }

    lines = scored_before(document).splitlines()

    assert lines[0] == (
        "The test split was scored 2 times before this report; "
        "every run is in `eval/results/test-runs.jsonl`:"
    )
    assert lines[1] == ""
    assert lines[2] == (
        "- 2026-10-23, commit `755e0cd4cacf` with uncommitted changes, 200 texts, rules only: "
        "a trial of the nightly command."
    )
    assert lines[3] == "- 2026-10-23, commit `d5d61cde64a4`, 973 texts, all three configs."
    assert scored_before({"test_runs": 0}) == (
        "The test split was scored 0 times before this report; "
        "every run is in `eval/results/test-runs.jsonl`."
    )
    assert plural(1, "time") == "1 time" and plural(2, "time") == "2 times"
    assert describe_configs(["combined", "rules"]) == "combined, rules"


def test_the_log_is_read_line_by_line_and_a_missing_log_is_empty(tmp_path: Path) -> None:
    assert earlier_runs(tmp_path / "none.jsonl") == []
    log = tmp_path / "runs.jsonl"
    log.write_text('{"n": 1}\n\n{"n": 2}\n')

    assert [entry["n"] for entry in earlier_runs(log)] == [1, 2]


def configs_with(rules: float, older: float | None, now: float | None) -> dict[str, Any]:
    def one(recall: float | None) -> dict[str, Any]:
        point = None if recall is None else {"recall": recall}
        return {"roc_auc": 0.9, "recall_at_fpr_5pct": point}

    configs = {"rules": one(rules)}
    if older is not None:
        configs["previous_combined"] = one(older)
    if now is not None:
        configs["combined"] = one(now)
    return configs


NAMES = names_of(
    {
        "scanner": {"window_tokens": 128, "window_overlap": 64},
        "previous_scanner": {"window_tokens": 510, "window_overlap": 64},
    }
)


def test_the_names_of_the_rows_say_the_windows_each_one_reads_in() -> None:
    assert NAMES["rules"] == "Rules"
    assert NAMES["classifier"] == "Model, windows of 128"
    assert NAMES["previous_classifier"] == "Model, windows of 510 (Phase 7)"
    assert NAMES["previous_combined"] == "Higher of the two, windows of 510 (Phase 7)"
    assert NAMES["combined"] == "Rules first, then the model"
    assert NAMES["previous_combined_300ms"].endswith("300 ms wait")


def test_the_reading_says_which_row_finds_most_and_how_the_older_join_did() -> None:
    configs = configs_with(0.59, 0.35, 0.67)

    lines = reading(configs, ["rules", "previous_combined", "combined"], NAMES)

    assert len(lines) == 2 and lines[1] == ""
    assert "the row that finds most is Rules first, then the model (0.67)" in lines[0]
    assert "The rules alone find 0.59." in lines[0]
    assert "found less than the rules alone (0.35 against 0.59)" in lines[0]
    assert "keeps every false positive of the model" in lines[0]


def test_the_reading_says_when_the_new_join_does_not_beat_the_rules() -> None:
    configs = configs_with(0.59, 0.35, 0.50)

    lines = reading(configs, ["rules", "previous_combined", "combined"], NAMES)

    assert "the row that finds most is Rules (0.59)" in lines[0]
    assert (
        "Rules first, then the model, finds less than the rules alone (0.50 against 0.59)"
        in (lines[0])
    )


def test_the_reading_has_nothing_to_add_with_fewer_than_two_rows_to_compare() -> None:
    assert reading(configs_with(0.59, None, None), ["rules"], NAMES) == []
    assert reading(configs_with(0.59, None, 0.6), ["rules", "combined"], NAMES)[0].startswith(
        "At a false positive rate of 5% or less the row that finds most is"
    )


def test_the_note_on_small_groups_gives_the_sizes_it_rests_on() -> None:
    configs = {
        "rules": {
            "hard_negatives": {
                "flag": {"of": 66},
                "by_family": {"howto": {"of": 16}, "security": {"of": 15}, "business": {"of": 19}},
            }
        }
    }

    assert small_groups(configs, ["rules"]) == [
        "- The test split has 66 hard negatives, and each kind of them is 15 to 19 texts. "
        "A rate over so few texts is wide, and the intervals above say how wide."
    ]
    assert small_groups(configs, []) == []


def test_the_counts_of_the_dataset_add_up_to_what_the_text_says() -> None:
    facts = dataset_facts(build(download=False))

    # Documents are what is neither a public prompt nor a hard negative, so the three parts of the
    # text (public, documents and hard negatives) cover the dataset once.
    kinds = facts["kinds"]
    assert sum(kinds.values()) == sum(facts["counts"].values())
    assert kinds["hard_negative"] == 150
    assert (
        facts["counts"]["synthetic"] - kinds["hard_negative"]
        == kinds["indirect"] + kinds["negative"]
    )


def test_a_saved_report_is_rendered_again_without_scoring_or_logging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: dict[str, Any]
) -> None:
    saved = tmp_path / "detector-2026-10-23.json"
    saved.write_text(json.dumps(document))
    doc = tmp_path / "results.md"
    monkeypatch.setattr(report, "RESULTS_DOC", doc)
    monkeypatch.setattr(run, "RUN_LOG", tmp_path / "runs.jsonl")

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the test split was read")

    monkeypatch.setattr(report, "build", refuse)
    monkeypatch.setattr(report, "build_document", refuse)

    status = report.main(["--render", str(saved)])

    assert status == 0
    assert render_section(document).strip() in doc.read_text()
    assert not (tmp_path / "runs.jsonl").exists()


def test_the_committed_results_document_is_what_the_tool_renders_from_the_committed_report() -> (
    None
):
    latest = sorted((ROOT / "eval" / "results").glob("detector-*.json"))[-1]
    document = json.loads(latest.read_text(encoding="utf-8"))
    text = (ROOT / "docs" / "results.md").read_text(encoding="utf-8")

    assert text.count(START) == 1 and text.count(END) == 1
    between = text.split(START)[1].split(END)[0]
    # A hand edit of the document, or of the report, or of the code that words it, shows here.
    # `python -m eval.detector.report --render <report>` writes the document again.
    assert between.strip() == render_section(document).strip()
    assert "Measured on " in between and " at commit `" in between


def test_the_row_for_the_wait_is_marked_as_a_weak_number(document: dict[str, Any]) -> None:
    section = render_section(document)
    threshold = document["result"]["configs"]["combined"]["recall_at_fpr_5pct"]["threshold"]

    assert "depends on the few harmless texts that score highest" in section
    assert f"The threshold of the rules first row sits at {threshold:.2f}" in section
    assert "not as a property of the detector" in section


# -- the passes, the dev section and the limits


def test_three_passes_of_the_scanner_make_the_configs_of_the_report(
    document: dict[str, Any],
) -> None:
    result = document["result"]

    assert set(result["configs"]) == {
        "rules",
        "combined",
        "combined_300ms",
        "classifier",
        "previous_classifier",
        "previous_combined",
        "previous_combined_300ms",
    }
    assert result["scanner"]["join"] == "rules_first"
    assert result["scanner"]["window_tokens"] == 128
    assert result["previous_scanner"]["join"] == "max"
    assert result["previous_scanner"]["window_tokens"] == 510


def test_the_scanner_as_phase_7_shipped_it_is_the_higher_of_the_two_over_windows_of_510() -> None:
    assert (
        report.PREVIOUS.join,
        report.PREVIOUS.window_tokens,
        report.PREVIOUS.window_overlap,
    ) == (
        "max",
        510,
        64,
    )


def test_the_model_alone_is_measured_on_every_text_and_the_joined_score_on_every_text(
    document: dict[str, Any],
) -> None:
    configs = document["result"]["configs"]
    total = document["result"]["samples"]["n"]

    for name in ("classifier", "combined", "previous_classifier", "previous_combined"):
        flag = configs[name]["flag"]
        assert flag["tp"] + flag["fp"] + flag["tn"] + flag["fn"] == total, name


def test_the_dev_section_gives_the_table_the_diagnosis_and_the_choice() -> None:
    lines = "\n".join(combination_sections(COMBINATION))

    assert lines.startswith("### How the join and the windows were picked, on the dev split")
    assert "`python -m eval.detector.combine` tried 320 candidates" in lines
    assert "(the rules alone find 0.52, whatever the windows)" in lines
    assert "| Windows of | Model alone | Higher of the two | Rules first, then" in lines
    assert "the model (weight 0.7) |" in lines
    assert "| 510 | 0.16 | 0.16 | 0.55 |" in lines
    assert "| 128 | 0.25 | 0.25 | 0.67 |" in lines
    assert "| documents with an attack | 100 | 78% | 36% | 64% |" in lines
    assert "finds +0.15 (95% +0.10 to +0.20) of the injections more than the rules alone" in lines
    assert "and the higher of the two over windows of 510 finds -0.36" in lines
    assert "The windows of 128 tokens with an overlap of 64 and the model weight of 0.7" in lines
    assert "(7 of the 463 injections)" in lines


def test_without_a_record_of_the_sweep_the_report_does_not_tell_how_the_choice_was_made() -> None:
    assert combination_sections(None) == []
    assert combination_sections({}) == []


def test_the_record_of_the_sweep_is_the_latest_dev_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(report, "RESULTS", tmp_path)
    assert combination_record() is None
    (tmp_path / "combination-dev-2026-10-22.json").write_text(json.dumps({"n": 1}))
    (tmp_path / "combination-dev-2026-10-24.json").write_text(json.dumps({"n": 2}))

    found = combination_record()

    assert found is not None and found["n"] == 2
    assert found["file"] == "combination-dev-2026-10-24.json"


def test_the_note_on_skipped_texts_says_how_many_the_model_was_not_asked_about() -> None:
    result = {"model_skipped": 301, "samples": {"n": 973}}

    note = skipped_note(result)

    assert "301 of the 973 texts of this run" in note[0] and note[1] == ""
    assert skipped_note({"model_skipped": 0, "samples": {"n": 973}}) == []


def test_the_kinds_of_attack_are_given_for_the_rules_the_older_join_and_the_new_one() -> None:
    def cells(**by_kind: tuple[int, int]) -> dict[str, Any]:
        return {
            kind: {"count": c, "of": n, "rate": c / n, "ci95": [0.0, 1.0]}
            for kind, (c, n) in by_kind.items()
        }

    def config(count: int) -> dict[str, Any]:
        return {
            "recall_by_family": cells(override=(count, 10)),
            "recall_by_hidden": cells(none=(count, 10)),
            "recall_by_template": cells(base64=(count, 10)),
        }

    configs = {"rules": config(1), "previous_combined": config(2), "combined": config(9)}

    text = "\n".join(kinds_of_attack(configs, NAMES))

    header = "| Family | Rules | Higher of the two, windows of 510 (Phase 7) | Rules first, then"
    assert header in text
    assert "| override | 0.10 (1 of 10, 95% 0.00 to 1.00) | 0.20 (2 of 10" in text
    assert "| Hidden with |" in text and "| Template |" in text and "| base64 |" in text


def test_the_limits_say_what_the_join_cannot_do_and_that_prompt_guard_was_not_run(
    document: dict[str, Any],
) -> None:
    text = "\n".join(limits(document, ["rules"]))

    assert "It reads in windows of 128 tokens that overlap by 64." in text
    assert "the model alone can flag a text and cannot make an injection of it" in text
    assert "picked on dev from 320 candidates" in text
    assert "Prompt Guard 2 (`prompt-guard-2-86m`) was not measured" in text
    assert "Images are not read by the scanner" in text


def test_the_log_of_a_run_says_how_the_scanner_was_set(tmp_path: Path) -> None:
    result = {
        "thresholds": {"flag": 0.5, "taint": 0.85},
        "limit": None,
        "samples": {"n": 973},
        "scanner": {"join": "rules_first", "model_weight": 0.7, "window_tokens": 128},
        "previous_scanner": {"join": "max", "window_tokens": 510},
        "configs": {
            "rules": {
                "recall_at_fpr_5pct": {"recall": 0.5},
                "hard_negatives": {"flag": {"rate": 0.25}},
            }
        },
    }
    log = tmp_path / "runs.jsonl"

    run.log_test_run(result, log)

    [line] = [json.loads(entry) for entry in log.read_text().splitlines()]
    assert line["scanner"]["join"] == "rules_first" and line["previous_scanner"]["join"] == "max"
    assert describe_configs(["rules", "previous_combined", "combined", "classifier"]) == (
        "the scanner as it is set now and as Phase 7 shipped it"
    )
