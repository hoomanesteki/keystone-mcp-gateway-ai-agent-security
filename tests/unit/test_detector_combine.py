"""KS-792: the sweep that picked the join, on scores made up so that the answers can be checked.

Nothing here loads a model or reads the real dataset. The windows' scores are written by hand, and
the engine that cuts a text into windows is given a fake tokenizer and a fake model.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from eval.detector import combine
from eval.detector.combine import (
    Combiner,
    Shape,
    Text,
    aggregate,
    batch_size_for,
    best_first,
    bootstrap,
    candidate_scores,
    choose,
    combiners,
    diagnose,
    eligible,
    gated,
    measure,
    never_lowers,
    noisy_or,
    only_rules,
    read_windows,
    scaled_max,
    score_windows,
    shipped,
    smoothed,
    weighted_sum,
    when_silent,
    windows_path,
)
from eval.detector.datasets import Sample
from keystone.defense.classifier import WindowedEngine
from keystone.defense.scanner import rules_first
from keystone.settings import ScannerSettings

pytestmark = pytest.mark.phase(9)

ROOT = Path(__file__).resolve().parents[2]

SHAPE = Shape(128, 64)


def sample(name: str, label: int, kind: str, carrier: str | None = None) -> Sample:
    return Sample(name, "x", label, kind, carrier or name, "dev", "synthetic", {})


def text(
    name: str, label: int, kind: str, rules: float, *windows: float, carrier: str | None = None
) -> Text:
    spans = [(i * 64, i * 64 + 128, score) for i, score in enumerate(windows)]
    return Text(sample(name, label, kind, carrier), rules, {SHAPE.key: spans})


# -- shapes


def test_a_shape_is_parsed_from_its_key_and_named_by_it() -> None:
    shape = Shape.parse("128/64")

    assert (shape.size, shape.overlap, shape.key) == (128, 64, "128/64")
    assert Shape.parse(Shape(510, 64).key) == Shape(510, 64)


def test_a_small_window_goes_in_bigger_batches_than_a_large_one() -> None:
    assert batch_size_for(Shape(510, 64)) == 4
    assert batch_size_for(Shape(64, 32)) > batch_size_for(Shape(128, 64)) > 4


def test_the_windows_are_kept_for_dev_in_a_file_named_by_the_shape() -> None:
    assert windows_path(Shape(128, 64)).name == "windows-dev-128-64.jsonl"


# -- the model's score of every window


def numbered(count: int) -> str:
    return " ".join(f"w{i}" for i in range(count))


def test_every_window_is_scored_and_none_is_left_out_early() -> None:
    seen: list[list[int]] = []

    def infer(rows: list[list[int]]) -> list[float]:
        seen.extend(rows)
        return [1.0 if 150 in row else 0.0 for row in rows]  # token 150 is in two windows

    engine = WindowedEngine(
        lambda t: [int(w[1:]) for w in t.split()],
        infer,
        100_001,
        100_002,
        max_length=130,
        stride=64,
    )
    ids = engine.tokenize(numbered(400))

    scored = score_windows(engine, ids, Shape(128, 64))

    assert [(a, b) for a, b, _ in scored] == [
        (0, 128),
        (64, 192),
        (128, 256),
        (192, 320),
        (256, 384),
        (320, 400),
    ]
    # A clear injection in the first window does not end the scan: the other windows are scored.
    assert [score for _, _, score in scored] == [0.0, 1.0, 1.0, 0.0, 0.0, 0.0]
    assert len(seen) == 6 and all(row[0] == 100_001 and row[-1] == 100_002 for row in seen)


def test_the_kept_windows_are_read_back(tmp_path: Path) -> None:
    path = tmp_path / "windows.jsonl"
    path.write_text(
        json.dumps({"id": "a", "tokens": 200, "windows": [[0, 128, 0.25], [64, 192, 0.5]]})
        + "\n"
        + json.dumps({"id": "b", "tokens": 3, "windows": [[0, 3, 0.75]]})
        + "\n"
    )

    assert read_windows(path) == {"a": [(0, 128, 0.25), (64, 192, 0.5)], "b": [(0, 3, 0.75)]}


# -- one score for a text


def test_the_highest_window_is_the_score_and_a_text_with_no_window_is_zero() -> None:
    windows = [(0, 128, 0.25), (64, 192, 0.75), (128, 256, 0.5)]

    assert aggregate(windows, "max") == 0.75
    assert aggregate([], "max") == aggregate([], "top2") == 0.0


def test_top2_needs_two_windows_to_agree() -> None:
    windows = [(0, 128, 1.0), (64, 192, 0.0), (128, 256, 0.5)]

    assert aggregate(windows, "top2") == pytest.approx(0.75)
    assert aggregate([(0, 3, 0.9)], "top2") == 0.9
    with pytest.raises(ValueError, match="mean"):
        aggregate(windows, "mean")


# -- the joins


def test_the_noisy_or_adds_the_model_as_a_second_witness() -> None:
    assert noisy_or(0.7)(0.4, 0.5) == pytest.approx(1 - 0.6 * 0.65)
    assert noisy_or(0.7)(0.4, None) == 0.4
    assert scaled_max(0.7)(0.4, 1.0) == pytest.approx(0.7)
    assert scaled_max(0.7)(0.9, 1.0) == 0.9


def test_a_gate_leaves_the_rules_alone_from_its_floor_up() -> None:
    join, skips = gated(0.5, noisy_or(1.0))

    assert join(0.5, 1.0) == 0.5 and skips(0.5)
    assert join(0.4, 1.0) == 1.0 and not skips(0.4)


def test_when_silent_counts_the_model_only_for_a_text_no_rule_hit() -> None:
    join, skips = when_silent(0.7)

    assert join(0.0, 1.0) == pytest.approx(0.7) and not skips(0.0)
    assert join(0.2, 1.0) == 0.2 and skips(0.2)


def test_the_shipped_join_is_the_function_of_the_scanner() -> None:
    candidate = shipped(0.5, 0.7)

    for rules in (0.0, 0.2, 0.4, 0.5, 0.88):
        for model in (None, 0.0, 0.6, 1.0):
            assert candidate.join(rules, model) == rules_first(rules, model, floor=0.5, weight=0.7)
    assert candidate.skips(0.5) and not candidate.skips(0.4)
    assert candidate.describe() == {"name": "rules_first", "params": {"floor": 0.5, "weight": 0.7}}


def test_only_the_weighted_sum_can_lower_a_score_the_rules_gave() -> None:
    pairs = [(rules, model) for rules in (0.0, 0.4, 0.88) for model in (0.0, 0.5, 1.0)]

    assert never_lowers(only_rules, pairs)
    assert never_lowers(noisy_or(0.7), pairs)
    assert never_lowers(scaled_max(0.7), pairs)
    assert never_lowers(shipped(0.5, 0.7).join, pairs)
    assert not never_lowers(weighted_sum(0.5), pairs)  # 0.88 and a model of 0 gives 0.44


def test_every_join_that_is_tried_has_a_name_and_the_shipped_one_is_among_them() -> None:
    tried = combiners()

    assert len({(c.name, tuple(c.params.items())) for c in tried}) == len(tried)
    assert {"rules", "max", "rules_first", "noisy_or", "weighted_sum"} <= {c.name for c in tried}
    assert shipped(0.5, 0.7).describe() in [c.describe() for c in tried]
    pairs = [(r, m) for r in (0.0, 0.3, 0.6, 0.9) for m in (0.0, 0.5, 1.0)]
    cannot_ship = {c.name for c in tried if not never_lowers(c.join, pairs)}
    # The model alone and the weighted sum can give a text less than the rules did.
    assert cannot_ship == {"model", "weighted_sum"}


# -- measuring a candidate


def toy() -> list[Text]:
    """Eight injections and 12 harmless texts. Of the injections the rules find two (0.7), the model
    finds four more (0.98), and two nobody finds. Of the harmless ones the model is sure about
    two, which are a hard negative and a document (0.99), and a rule hits one (0.6)."""
    found = [text(f"a{i}", 1, "indirect", 0.7, 0.1) for i in range(2)]
    found += [text(f"b{i}", 1, "indirect", 0.0, 0.98) for i in range(4)]
    found += [text(f"c{i}", 1, "public", 0.0, 0.1) for i in range(2)]
    found += [text("h0", 0, "hard_negative", 0.0, 0.99), text("h1", 0, "negative", 0.0, 0.99)]
    found += [text("h2", 0, "negative", 0.6, 0.0)]
    found += [text(f"n{i}", 0, "negative", 0.0, 0.0) for i in range(9)]
    return found


def test_the_higher_of_the_two_pays_for_every_false_positive_of_the_model() -> None:
    texts = toy()
    max_join = Combiner("max", combine.highest)

    row = measure(texts, SHAPE, "max", max_join)

    # 12 harmless texts: one false positive is 8 percent, over the 5 percent allowed, so no
    # threshold that finds anything is allowed. The threshold that flags nothing finds nothing.
    assert row["recall_at_fpr_5pct"] == 0.0 and row["threshold"] is None
    assert row["model_asked"] == 1.0


def test_the_rules_first_join_finds_what_the_rules_and_the_sure_model_find_apart() -> None:
    texts = toy() + [text(f"extra{i}", 0, "negative", 0.0, 0.0) for i in range(20)]
    # 32 harmless texts now, so one false positive (3 percent) is allowed.
    rules = measure(texts, SHAPE, "max", Combiner("rules", only_rules))
    joined = measure(texts, SHAPE, "max", shipped(0.5, 0.7))

    assert rules["recall_at_fpr_5pct"] == pytest.approx(2 / 8)
    # The model's 0.99 texts count 0.693 and the rules' 0.6 text is under that, so with the 0.7 of
    # the rules' hits first the threshold lands at the model's 0.98 (0.686): both of its false
    # positives are in, which is two of 32 (6 percent) and over the 5 percent.
    assert joined["fpr"] <= 0.05
    assert joined["recall_at_fpr_5pct"] >= rules["recall_at_fpr_5pct"]
    assert joined["model_asked"] < 1.0  # the two texts the rules flag are not given to the model


def test_the_row_says_where_the_attacks_were_found_by_kind_of_text() -> None:
    texts = toy() + [text(f"extra{i}", 0, "negative", 0.0, 0.0) for i in range(40)]

    row = measure(texts, SHAPE, "max", shipped(0.5, 0.7))

    assert row["shape"] == "128/64" and row["aggregate"] == "max"
    assert row["combiner"] == {"name": "rules_first", "params": {"floor": 0.5, "weight": 0.7}}
    assert row["recall_documents"] is not None and row["recall_public"] is not None
    assert row["hard_negatives_flagged"] is not None
    assert row["recall_ci95"][0] <= row["recall_at_fpr_5pct"] <= row["recall_ci95"][1]


def test_candidate_scores_follow_the_texts() -> None:
    texts = toy()

    scores = candidate_scores(texts, SHAPE, "max", shipped(0.5, 0.7))

    assert len(scores) == len(texts)
    assert scores[0] == 0.7  # flagged by the rules: the model is not asked
    assert scores[2] == pytest.approx(0.7 * 0.98)


def test_a_tie_is_broken_by_what_the_candidate_costs() -> None:
    def row(shape: str, asked: float, params: int, recall: float = 0.6) -> dict[str, object]:
        return {
            "shape": shape,
            "model_asked": asked,
            "recall_at_fpr_5pct": recall,
            "combiner": {"name": "c", "params": {str(i): 1 for i in range(params)}},
        }

    rows = [
        row("64/32", 0.7, 2),
        row("128/64", 0.7, 2),
        row("128/64", 0.7, 1),
        row("128/64", 0.6, 3),
        row("512/64", 1.0, 0, recall=0.7),
    ]

    ordered = best_first(rows)

    assert ordered[0]["shape"] == "512/64"  # the best recall comes first whatever it costs
    assert [(r["model_asked"], len(r["combiner"]["params"]), r["shape"]) for r in ordered[1:]] == [  # type: ignore[index]
        (0.6, 3, "128/64"),
        (0.7, 1, "128/64"),
        (0.7, 2, "128/64"),
        (0.7, 2, "64/32"),
    ]


# -- why: the model on each kind of text


def test_the_diagnosis_counts_what_the_model_and_the_rules_flag_in_each_kind_of_text() -> None:
    texts = toy()

    found = diagnose(texts, [SHAPE])

    attack = found["documents with an attack"]
    assert attack["n"] == 6 and attack["rules_at_0.5"] == pytest.approx(2 / 6, abs=1e-4)
    assert attack["model"]["128/64"]["at_0.5"] == pytest.approx(4 / 6, abs=1e-4)
    hard = found["hard negatives"]
    assert hard["n"] == 1 and hard["model"]["128/64"] == {"at_0.5": 1.0, "at_0.95": 1.0}


# -- how much of it is luck


def candidates() -> dict[str, tuple[Shape, str, Combiner]]:
    return {
        "rules": (SHAPE, "max", Combiner("rules", only_rules)),
        "joined": (SHAPE, "max", shipped(0.5, 0.7)),
    }


def test_a_bootstrap_with_the_same_seed_gives_the_same_answer() -> None:
    texts = toy() + [text(f"extra{i}", 0, "negative", 0.0, 0.0) for i in range(30)]

    first = bootstrap(texts, candidates(), resamples=40, seed=3)
    second = bootstrap(texts, candidates(), resamples=40, seed=3)
    other = bootstrap(texts, candidates(), resamples=40, seed=4)

    assert first == second
    assert first != other
    assert first["reference"] == "rules" and set(first["gain_over_reference"]) == {"joined"}
    low, high = first["recall"]["joined"]["low"], first["recall"]["joined"]["high"]
    assert 0.0 <= low <= first["recall"]["joined"]["mean"] <= high <= 1.0


def test_a_carrier_is_resampled_with_every_text_made_from_it() -> None:
    # Two carriers: one with all the injections and one with all the harmless texts. A resample
    # that kept texts apart from their carrier could have injections and nothing else.
    texts = [text(f"p{i}", 1, "indirect", 0.9, 0.0, carrier="attacked") for i in range(4)] + [
        text(f"q{i}", 0, "negative", 0.0, 0.0, carrier="clean") for i in range(30)
    ]

    found = bootstrap(texts, {"rules": (SHAPE, "max", Combiner("rules", only_rules))}, resamples=30)

    # Whenever the resample has both kinds, the injections are all found; when it has one kind, the
    # recall is 0 by definition. Nothing in between.
    assert found["recall"]["rules"]["high"] in (0.0, 1.0)


# -- the choice


def row(
    shape: str,
    weight: float,
    recall: float,
    *,
    how: str = "max",
    name: str = "rules_first",
    floor: float = 0.5,
) -> dict[str, object]:
    return {
        "shape": shape,
        "aggregate": how,
        "combiner": {"name": name, "params": {"floor": floor, "weight": weight}},
        "recall_at_fpr_5pct": recall,
        "model_asked": 0.7,
    }


def test_the_gateway_can_run_the_rules_first_join_with_its_floor_at_the_flag_threshold() -> None:
    assert eligible(row("128/64", 0.7, 0.6))
    assert not eligible(row("128/64", 0.7, 0.6, floor=0.6))
    assert not eligible(row("128/64", 0.7, 0.6, name="gate_scaled_max"))
    assert not eligible(row("128/64", 0.7, 0.6, name="weighted_sum"))


def test_of_the_candidates_within_the_noise_the_larger_window_is_chosen() -> None:
    rows = [
        row("64/32", 0.7, 0.676),
        row("128/64", 0.7, 0.672),
        row("256/64", 0.7, 0.633),
        row("510/64", 0.7, 0.2),
    ]

    # 0.672 is within 1.5 points of 0.676, and 0.633 is not.
    assert choose(rows)["shape"] == "128/64"


def test_a_better_recall_outside_the_noise_beats_a_larger_window() -> None:
    rows = [row("64/32", 0.7, 0.70), row("128/64", 0.7, 0.67)]

    assert choose(rows)["shape"] == "64/32"


def test_a_join_the_gateway_cannot_run_is_never_chosen_however_well_it_did() -> None:
    rows = [
        row("128/64", 0.7, 0.9, name="gate_scaled_max"),
        row("128/64", 0.7, 0.9, floor=0.6),
        row("128/64", 0.7, 0.6),
    ]

    chosen = choose(rows)

    assert chosen["recall_at_fpr_5pct"] == 0.6 and eligible(chosen)


def test_with_nothing_the_gateway_can_run_there_is_nothing_to_choose() -> None:
    with pytest.raises(ValueError, match="no candidate"):
        choose([row("128/64", 0.7, 0.9, name="weighted_sum")])


def test_a_weight_in_the_middle_of_a_plateau_is_chosen_over_one_at_the_edge_of_a_drop() -> None:
    plateau = {0.6: 0.50, 0.65: 0.67, 0.7: 0.67, 0.75: 0.55, 0.8: 0.48}
    rows = [row("128/64", weight, recall) for weight, recall in plateau.items()]

    assert smoothed(rows[2], rows) == pytest.approx((0.67 + 0.67 + 0.55) / 3)
    assert smoothed(rows[1], rows) == pytest.approx((0.50 + 0.67 + 0.67) / 3)
    assert smoothed(rows[0], rows) == pytest.approx((0.50 + 0.67) / 2)
    assert choose(rows)["combiner"]["params"]["weight"] == 0.7  # type: ignore[index]


def test_the_max_aggregate_is_preferred_to_top2_when_nothing_else_tells_them_apart() -> None:
    rows = [row("128/64", 0.7, 0.67, how="top2"), row("128/64", 0.7, 0.67, how="max")]

    assert choose(rows)["aggregate"] == "max"


# -- the record of the sweep on dev and the defaults of the scanner


def latest_sweep() -> dict[str, Any]:
    found = sorted((ROOT / "eval" / "results").glob("combination-dev-*.json"))
    assert found, "the sweep on dev left no record in eval/results"
    record: dict[str, Any] = json.loads(found[-1].read_text(encoding="utf-8"))
    return record


def test_the_defaults_of_the_scanner_are_the_candidate_the_sweep_on_dev_chose() -> None:
    chosen = latest_sweep()["chosen"]
    size, _, overlap = chosen["shape"].partition("/")
    config = ScannerSettings()

    assert config.join == chosen["combiner"]["name"] == "rules_first"
    assert (config.window_tokens, config.window_overlap) == (int(size), int(overlap))
    assert config.model_weight == chosen["combiner"]["params"]["weight"]
    assert config.thresholds.suspicious == chosen["combiner"]["params"]["floor"]
    assert chosen["aggregate"] == "max"  # the engine takes the highest window


def test_the_choice_in_the_record_follows_from_the_rows_and_the_rule() -> None:
    record = latest_sweep()

    assert choose(record["rows"]) == record["chosen"]
    assert record["split"] == "dev"
    assert record["candidates"] == len(record["rows"])
    # Dev has 919 texts, 463 of them injections: the sweep never read the test split.
    assert (record["n"], record["injections"]) == (919, 463)
