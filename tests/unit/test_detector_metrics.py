"""KS-707: the metrics of the detector evaluation, on data small enough to check by hand."""

import pytest

from eval.detector.metrics import (
    Confusion,
    average_precision,
    bucket_of,
    confusion,
    latency_by_bucket,
    percentile,
    recall_at_fpr,
    roc_auc,
    wilson,
)

pytestmark = pytest.mark.phase(7)

# The example of scikit-learn's documentation: two injections (0.35 and 0.8) and two harmless
# texts (0.1 and 0.4).
SMALL_SCORES = [0.1, 0.4, 0.35, 0.8]
SMALL_LABELS = [0, 0, 1, 1]

# 20 harmless texts and 10 injections. The harmless ones score 0.10 to 0.28 (19 of them) and 0.92.
# The injections score 0.95, 0.93, 0.91, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4 and 0.15.
LOW = [round(0.10 + 0.01 * i, 2) for i in range(19)]
SCORES = [*LOW, 0.92, 0.95, 0.93, 0.91, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.15]
LABELS = [0] * 20 + [1] * 10


def test_metrics_on_toy_data() -> None:
    # The small example, as the documentation of scikit-learn has it.
    assert roc_auc(SMALL_SCORES, SMALL_LABELS) == pytest.approx(0.75)
    assert average_precision(SMALL_SCORES, SMALL_LABELS) == pytest.approx(5 / 6)
    point = recall_at_fpr(SMALL_SCORES, SMALL_LABELS, max_fpr=0.5)
    assert point is not None and (point.threshold, point.recall, point.fpr) == (0.35, 1.0, 0.5)

    # At 0.5, 8 of the 10 injections are flagged (0.95 down to 0.5) and one harmless text is (0.92).
    flagged = confusion(SCORES, LABELS, 0.5)
    assert flagged == Confusion(tp=8, fp=1, tn=19, fn=2)
    assert flagged.precision == pytest.approx(8 / 9)
    assert flagged.recall == pytest.approx(0.8)
    assert flagged.f1 == pytest.approx(2 * (8 / 9) * 0.8 / ((8 / 9) + 0.8))
    assert flagged.fpr == pytest.approx(0.05)

    # Flagging at most one harmless text in 20 (5 percent) finds 9 of the 10 injections, by the
    # threshold 0.4: below it the next harmless text, 0.28, is a second false positive.
    best = recall_at_fpr(SCORES, LABELS, max_fpr=0.05)
    assert best is not None and (best.threshold, best.recall, best.fpr) == (0.4, 0.9, 0.05)
    # Of the 200 pairs, an injection beats the harmless text in 178 and ties one in one (0.15).
    assert roc_auc(SCORES, LABELS) == pytest.approx(178.5 / 200)
    # Summed by hand over the scores where recall rises: 0.1 + 0.1 + 0.075 + 0.08 + 0.08333 +
    # 0.085714 + 0.0875 + 0.088889 + 0.09 + 0.04.
    assert average_precision(SCORES, LABELS) == pytest.approx(0.830437, abs=1e-5)


def test_f_beta_weighs_precision_and_recall() -> None:
    counts = Confusion(tp=8, fp=1, tn=19, fn=2)  # precision 8/9, recall 0.8

    assert counts.f_beta(1) == pytest.approx(counts.f1)
    # Counting precision twice as much as recall: 1.25 * p * r / (0.25 * p + r).
    assert counts.f_beta(0.5) == pytest.approx(1.25 * (8 / 9) * 0.8 / (0.25 * (8 / 9) + 0.8))
    assert counts.f_beta(0.5) > counts.f1 > counts.f_beta(2)
    assert Confusion(0, 0, 5, 0).f_beta(0.5) == 0.0


def test_a_threshold_is_at_or_above() -> None:
    assert confusion([0.5, 0.49], [1, 1], 0.5) == Confusion(tp=1, fp=0, tn=0, fn=1)


def test_empty_classes_give_no_rate_and_no_number_that_means_nothing() -> None:
    assert Confusion(0, 0, 0, 0).precision == 0.0
    assert Confusion(0, 0, 0, 0).recall == 0.0
    assert Confusion(0, 0, 0, 0).f1 == 0.0
    assert Confusion(0, 0, 0, 0).fpr == 0.0
    for labels in ([1, 1, 1], [0, 0, 0], []):
        scores = [0.5] * len(labels)
        assert roc_auc(scores, labels) is None
        assert average_precision(scores, labels) is None
        assert recall_at_fpr(scores, labels) is None


def test_scores_that_are_all_equal_are_a_coin() -> None:
    scores, labels = [0.5] * 4, [1, 0, 1, 0]

    assert roc_auc(scores, labels) == 0.5
    # The only threshold flags everything, which is a false positive rate of 1.
    point = recall_at_fpr(scores, labels)
    assert point is not None and (point.threshold, point.recall, point.fpr) == (None, 0.0, 0.0)


def test_a_perfect_and_a_backwards_detector() -> None:
    labels = [0, 0, 0, 1, 1]

    assert roc_auc([0.1, 0.2, 0.3, 0.8, 0.9], labels) == 1.0
    assert average_precision([0.1, 0.2, 0.3, 0.8, 0.9], labels) == 1.0
    assert roc_auc([0.9, 0.8, 0.7, 0.2, 0.1], labels) == 0.0
    perfect = recall_at_fpr([0.1, 0.2, 0.3, 0.8, 0.9], labels)
    assert perfect is not None and perfect.recall == 1.0 and perfect.fpr == 0.0


def test_lengths_must_match() -> None:
    for function in (roc_auc, average_precision, recall_at_fpr, confusion):
        with pytest.raises(ValueError, match="one label for each score"):
            function([0.5], [1, 0], *([0.5] if function is confusion else []))  # type: ignore[operator]


def test_a_rate_has_an_interval_that_tells_how_few_texts_it_rests_on() -> None:
    low, high = wilson(15, 75) or (0, 0)

    assert (low, high) == pytest.approx((0.1251, 0.3041), abs=1e-4)
    assert wilson(0, 75) == pytest.approx((0.0, 0.0487), abs=1e-4)
    assert wilson(75, 75) == pytest.approx((0.9513, 1.0), abs=1e-4)
    assert wilson(0, 0) is None


def test_percentiles_are_nearest_rank() -> None:
    values = list(range(1, 21))

    assert percentile(values, 50) == 10
    assert percentile(values, 95) == 19
    assert percentile(values, 100) == 20
    assert percentile([7.0], 95) == 7.0
    assert percentile([3, 1, 2], 50) == 2  # it sorts
    with pytest.raises(ValueError, match="no values"):
        percentile([], 50)


def test_the_length_buckets_are_those_of_the_spike() -> None:
    assert [bucket_of(t) for t in (0, 499.9, 500, 1999, 2000, 2000.1, 50_000)] == [
        "under 500",
        "under 500",
        "500 to 2000",
        "500 to 2000",
        "500 to 2000",
        "over 2000",
        "over 2000",
    ]


def test_latency_is_reported_for_each_bucket_with_how_many_texts_it_rests_on() -> None:
    timings = [(100, 1.0), (200, 2.0), (300, 3.0), (800, 10.0), (3000, 100.0)]

    table = latency_by_bucket(timings)

    assert table["under 500"] == {"n": 3, "p50_ms": 2.0, "p95_ms": 3.0}
    assert table["500 to 2000"] == {"n": 1, "p50_ms": 10.0, "p95_ms": 10.0}
    assert table["over 2000"] == {"n": 1, "p50_ms": 100.0, "p95_ms": 100.0}
    assert latency_by_bucket([])["under 500"] == {"n": 0, "p50_ms": None, "p95_ms": None}


def test_nothing_in_the_module_needs_a_package_that_ci_does_not_have() -> None:
    import eval.detector.metrics as module

    source = open(module.__file__, encoding="utf-8").read()  # noqa: SIM115
    imports = {
        line.split()[1].split(".")[0] for line in source.splitlines() if line.startswith("import ")
    }
    imports |= {
        line.split()[1].split(".")[0] for line in source.splitlines() if line.startswith("from ")
    }

    assert imports <= {"__future__", "math", "collections", "dataclasses"}
