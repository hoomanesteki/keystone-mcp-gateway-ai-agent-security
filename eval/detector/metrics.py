"""The numbers of the detector evaluation, in plain Python (KS-707).

A detector gives a score between 0 and 1, and a text is flagged when its score is at or above a
threshold. These functions say how good the scores are:

- `confusion`: what a threshold gets right and wrong, with precision, recall, F1 and the false
  positive rate.
- `roc_auc`: the chance that a random injection scores higher than a random harmless text (ties
  count half). 1 is perfect and 0.5 is a coin.
- `average_precision`: the area under the precision-recall curve, summed over the distinct scores
  (the definition of scikit-learn's `average_precision_score`, with no interpolation). It depends
  on how many injections there are among the texts, so it is only comparable between runs on the
  same data.
- `recall_at_fpr`: the most injections found while flagging at most 5 percent of the harmless
  texts. Unlike precision and recall it does not depend on the threshold that was configured, so it
  is the number to compare detectors by.
- `wilson`: a 95 percent interval for a proportion. 75 hard negatives is not many, and a rate of
  0.20 over 75 texts could be 0.12 or 0.30.
- `percentile` and `latency_by_bucket`: the time a scan takes, for texts under 500 tokens, from
  500 to 2,000 and over 2,000 (four characters make a token).

There are no dependencies, so the nightly job needs none. A function that needs both kinds of label
and gets one returns None and not a number that means nothing.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

BUCKETS = (("under 500", 0, 500), ("500 to 2000", 500, 2000), ("over 2000", 2000, math.inf))


@dataclass(frozen=True)
class Confusion:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def precision(self) -> float:
        flagged = self.tp + self.fp
        return self.tp / flagged if flagged else 0.0

    @property
    def recall(self) -> float:
        positives = self.tp + self.fn
        return self.tp / positives if positives else 0.0

    @property
    def f1(self) -> float:
        total = self.precision + self.recall
        return 2 * self.precision * self.recall / total if total else 0.0

    def f_beta(self, beta: float) -> float:
        """The F score that counts recall `beta` times as much as precision. F1 is `beta` 1, and
        F0.5 counts precision twice as much as recall."""
        weight = beta * beta * self.precision + self.recall
        return (1 + beta * beta) * self.precision * self.recall / weight if weight else 0.0

    @property
    def fpr(self) -> float:
        negatives = self.fp + self.tn
        return self.fp / negatives if negatives else 0.0


def confusion(scores: Sequence[float], labels: Sequence[int], threshold: float) -> Confusion:
    """A text is flagged when its score is at or above `threshold`."""
    if len(scores) != len(labels):
        raise ValueError("there must be one label for each score")
    tp = fp = tn = fn = 0
    for score, label in zip(scores, labels, strict=True):
        flagged = score >= threshold
        if label:
            tp, fn = (tp + 1, fn) if flagged else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if flagged else (fp, tn + 1)
    return Confusion(tp, fp, tn, fn)


def _both_kinds(labels: Sequence[int]) -> bool:
    return 0 < sum(1 for label in labels if label) < len(labels)


def roc_auc(scores: Sequence[float], labels: Sequence[int]) -> float | None:
    """The area under the ROC curve, from the ranks of the scores (Mann-Whitney). Equal scores
    share the mean of their ranks. None when the labels are all one kind."""
    if len(scores) != len(labels):
        raise ValueError("there must be one label for each score")
    if not _both_kinds(labels):
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    start = 0
    while start < len(order):
        end = start
        while end + 1 < len(order) and scores[order[end + 1]] == scores[order[start]]:
            end += 1
        mean_rank = (start + end) / 2 + 1  # ranks start at 1
        for position in range(start, end + 1):
            ranks[order[position]] = mean_rank
        start = end + 1
    positives = [rank for rank, label in zip(ranks, labels, strict=True) if label]
    n_pos, n_neg = len(positives), len(labels) - len(positives)
    return (sum(positives) - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def _curve(scores: Sequence[float], labels: Sequence[int]) -> list[tuple[float, int, int]]:
    """(threshold, true positives, false positives) for each distinct score, highest first: what
    flagging everything at or above that score finds."""
    ranked = sorted(zip(scores, labels, strict=True), key=lambda pair: -pair[0])
    points: list[tuple[float, int, int]] = []
    tp = fp = 0
    for index, (score, label) in enumerate(ranked):
        tp, fp = (tp + 1, fp) if label else (tp, fp + 1)
        last = index + 1 == len(ranked) or ranked[index + 1][0] != score
        if last:
            points.append((score, tp, fp))
    return points


def average_precision(scores: Sequence[float], labels: Sequence[int]) -> float | None:
    """The sum over the distinct scores of the rise in recall times the precision there. None
    when there are no injections or nothing harmless."""
    if len(scores) != len(labels):
        raise ValueError("there must be one label for each score")
    if not _both_kinds(labels):
        return None
    positives = sum(1 for label in labels if label)
    total = 0.0
    previous = 0
    for _, tp, fp in _curve(scores, labels):
        total += (tp - previous) / positives * (tp / (tp + fp))
        previous = tp
    return total


@dataclass(frozen=True)
class OperatingPoint:
    """What a threshold does: it flags `recall` of the injections and `fpr` of the harmless texts.
    A threshold of None flags nothing."""

    threshold: float | None
    recall: float
    fpr: float


def recall_at_fpr(
    scores: Sequence[float], labels: Sequence[int], max_fpr: float = 0.05
) -> OperatingPoint | None:
    """The threshold that finds the most injections while flagging at most `max_fpr` of the
    harmless texts. Of equal recalls the highest threshold wins, the one that flags least. None
    when the labels are all one kind."""
    if len(scores) != len(labels):
        raise ValueError("there must be one label for each score")
    if not _both_kinds(labels):
        return None
    positives = sum(1 for label in labels if label)
    negatives = len(labels) - positives
    best = OperatingPoint(None, 0.0, 0.0)
    for threshold, tp, fp in _curve(scores, labels):
        point = OperatingPoint(threshold, tp / positives, fp / negatives)
        if point.fpr <= max_fpr and point.recall > best.recall:
            best = point
    return best


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float] | None:
    """The Wilson score interval of a proportion: 95 percent with the default z. None for no
    trials."""
    if total <= 0:
        return None
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return max(0.0, centre - half), min(1.0, centre + half)


def percentile(values: Sequence[float], q: float) -> float:
    """The nearest-rank percentile: the smallest value that at least `q` percent of them are at or
    under. For 20 timings the 95th is the 19th of the sorted list."""
    if not values:
        raise ValueError("there are no values")
    ranked = sorted(values)
    index = max(0, math.ceil(q / 100 * len(ranked)) - 1)
    return ranked[min(index, len(ranked) - 1)]


def bucket_of(tokens: float) -> str:
    for name, low, high in BUCKETS:
        if low <= tokens < high or (name == "500 to 2000" and tokens == 2000):
            return name
    return BUCKETS[-1][0]


def latency_by_bucket(
    timings: Sequence[tuple[float, float]],
) -> dict[str, dict[str, float | int | None]]:
    """For each length bucket the number of texts and the p50 and p95 of the time of a scan in
    milliseconds. `timings` is (tokens, milliseconds) for each text. A bucket with no text has
    None for the percentiles. 2,000 tokens is in the middle bucket, as the spike counts it."""
    table: dict[str, dict[str, float | int | None]] = {}
    for name, _, _ in BUCKETS:
        times = [ms for tokens, ms in timings if bucket_of(tokens) == name]
        table[name] = {
            "n": len(times),
            "p50_ms": percentile(times, 50) if times else None,
            "p95_ms": percentile(times, 95) if times else None,
        }
    return table
