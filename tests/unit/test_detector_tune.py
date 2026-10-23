"""KS-707: thresholds are chosen on the dev split, by a rule written down before the numbers.

The sweep and the choice are tested on scores made up so that the answer is known. The command is
tested on the rules and the real dev split, from a file of scores, and it refuses the test split.
"""

import json
from pathlib import Path

import pytest

from eval.detector import tune
from eval.detector.datasets import Sample, build
from eval.detector.run import Scored, score_rules, write_scores
from eval.detector.tune import GRID, PRECISION_FLOOR, recommend, render, sweep
from keystone.settings import ScannerSettings

pytestmark = pytest.mark.phase(7)


def scored(name: str, label: int, score: float, kind: str = "negative") -> Scored:
    sample = Sample(name, "x", label, kind, name, "dev", "synthetic", {"family": "howto"})
    return Scored(sample, score, None, score, 0.1)


def made_up() -> list[Scored]:
    """Ten injections at 0.9 (all strong) and 0.45 (the weak rule alone), twenty harmless texts at
    0 and five at 0.45 (how-to guides that sound like orders). Hard negatives are among the last."""
    found = [scored(f"a{i}", 1, 0.9) for i in range(6)]
    found += [scored(f"w{i}", 1, 0.45) for i in range(4)]
    found += [scored(f"n{i}", 0, 0.0) for i in range(20)]
    found += [scored(f"h{i}", 0, 0.45, "hard_negative") for i in range(5)]
    return found


def test_the_sweep_says_what_each_threshold_does() -> None:
    rows = {row["threshold"]: row for row in sweep(made_up(), "rules")}

    assert set(rows) == set(GRID)
    # At 0.5 only the six strong injections are found, and nothing harmless is flagged.
    assert rows[0.5]["precision"] == 1.0 and rows[0.5]["recall"] == 0.6
    assert rows[0.5]["fpr"] == 0.0 and rows[0.5]["hard_negative_fpr"] == 0.0
    # At 0.45 the weak ones come in and so do the five that sound like orders.
    assert rows[0.45]["recall"] == 1.0
    assert rows[0.45]["precision"] == pytest.approx(10 / 15, abs=1e-4)
    assert rows[0.45]["hard_negative_fpr"] == 1.0
    assert rows[0.45]["fpr"] == pytest.approx(5 / 25, abs=1e-4)


def test_the_choice_counts_precision_twice_and_takes_the_higher_threshold_of_a_tie() -> None:
    chosen = recommend(sweep(made_up(), "rules"))

    # F0.5 is highest where nothing harmless is flagged, and the same from 0.5 to 0.9: the highest
    # of those is 0.9, where the strong ones are still all found.
    assert chosen["suspicious"] == 0.9
    assert chosen["precision_floor"] == PRECISION_FLOOR


def test_a_taint_needs_a_precision_that_a_flag_does_not() -> None:
    rows = sweep(made_up(), "rules")

    chosen = recommend(rows)

    # Precision is 1.0 at 0.9, so the lowest threshold from the flag up that reaches 0.95 is 0.9.
    assert chosen["injection"] == 0.9


def test_when_no_threshold_is_precise_enough_there_is_no_taint_threshold() -> None:
    noisy = [scored(f"a{i}", 1, 0.9) for i in range(5)] + [
        scored(f"n{i}", 0, 0.9) for i in range(5)
    ]

    assert recommend(sweep(noisy, "rules"))["injection"] is None


def test_the_table_marks_the_two_choices() -> None:
    rows = sweep(made_up(), "rules")

    table = render(rows, {"suspicious": 0.5, "injection": 0.9})

    lines = table.splitlines()
    assert lines[0].startswith("threshold")
    assert len(lines) == 1 + len(GRID)
    assert next(line for line in lines if "<- suspicious" in line).lstrip().startswith("0.50")
    assert next(line for line in lines if "<- injection" in line).lstrip().startswith("0.90")


def test_with_no_hard_negatives_that_column_says_it_was_not_measured() -> None:
    plain = [i for i in made_up() if i.sample.kind != "hard_negative"]

    rows = sweep(plain, "rules")
    table = render(rows, {"suspicious": 0.5, "injection": 0.9})

    assert all(row["hard_negative_fpr"] is None for row in rows)
    assert "n/a" in table and "None" not in table


def test_only_the_texts_a_model_scored_count_for_the_model() -> None:
    both = made_up()
    both[0] = Scored(both[0].sample, 0.9, 0.95, 0.95, 0.1)  # the one text the model scored

    rows = sweep(both, "classifier")

    # One injection and nothing else: the others were never scored by the model.
    assert rows[0]["recall"] == 1.0 and rows[0]["precision"] == 1.0 and rows[0]["fpr"] == 0.0


def test_the_command_refuses_the_test_split(capsys: pytest.CaptureFixture[str]) -> None:
    status = tune.main(["--split", "test"])

    assert status == 2
    assert "dev only" in capsys.readouterr().err


def test_the_command_tunes_on_dev_from_a_file_of_scores(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = build(download=False)
    scores = tmp_path / "scores.jsonl"
    write_scores(score_rules(data.split("dev"), ScannerSettings(classifier="none")), scores)
    out = tmp_path / "tuning.json"

    status = tune.main(
        ["--config", "rules", "--offline", "--scores", str(scores), "--out", str(out)]
    )

    assert status == 0
    written = json.loads(out.read_text())
    assert written["split"] == "dev" and written["config"] == "rules"
    assert written["n"] == len(data.split("dev"))
    assert [row["threshold"] for row in written["grid"]] == GRID
    assert written["current"] == {"suspicious": 0.5, "injection": 0.85}
    assert set(written["criteria"]) == {"suspicious", "injection"}
    printed = capsys.readouterr().out
    assert "recommended:" in printed and "configured:" in printed
