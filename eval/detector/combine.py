"""Try other ways to join the rules and the model, on the dev split only (KS-792, ADR-0011).

    python -m eval.detector.combine windows --shape 128/64     # score every window of dev
    python -m eval.detector.combine sweep --out eval/results/combination-dev-<date>.json

The report of Phase 7 found that the higher of the two scores (`max`) finds fewer attacks than the
rules alone at a false positive rate of 5 percent, and that the model is weak on documents. This
module is where the remedies were tried. It reads `dev` and nothing else: `windows` refuses `test`,
and the one look at `test` is made by `report.py` after a way has been picked from the sweep.

Two steps, so that the model runs once for each shape of window and the joins cost nothing to try:

- `windows` cuts every text of dev into windows of one shape (`size` tokens of the text, `overlap`
  of them shared with the window before) and keeps the model's score of every window, not only the
  highest. It takes minutes for each shape, and the scores are kept in `eval/data/`, which is not
  committed.
- `sweep` reads the kept scores, takes one model score for a text (`aggregate`), joins it with the
  rules' score (`combiners`) and measures the result with the metrics of the report. Every
  candidate is a shape, an aggregate and a join, and the sweep ranks them by recall at a false
  positive rate of 5 percent.

The join that ships is `keystone.defense.scanner.rules_first`, the very function the gateway calls,
so what is measured here is what runs there. A join that is to ship must never give a text less than
the rules gave it (`never_lowers`): the rules alone taint the session of the headline demo, and a
join that let the model overrule them would make the demo depend on the classifier.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.detector.datasets import DATA_DIR, Dataset, Sample, build
from eval.detector.metrics import recall_at_fpr, roc_auc, wilson
from eval.detector.run import FPR_BUDGET
from keystone.defense.classifier import SPECS, WindowedEngine, build_engine, split_windows
from keystone.defense.rules import prepare, reveal_tags
from keystone.defense.scanner import build_scanner, rules_first
from keystone.settings import ScannerSettings

# (first token, one past the last token, the model's score) of one window.
WindowScore = tuple[int, int, float]
Join = Callable[[float, float | None], float]


@dataclass(frozen=True)
class Shape:
    """How a text is cut: windows of `size` tokens of the text (the two special tokens come on
    top), each sharing `overlap` tokens with the one before."""

    size: int
    overlap: int

    @property
    def key(self) -> str:
        return f"{self.size}/{self.overlap}"

    @classmethod
    def parse(cls, key: str) -> Shape:
        size, _, overlap = key.partition("/")
        return cls(int(size), int(overlap))


# 510 and 64 are what the gateway ran with up to Phase 8: windows of 512 tokens with the two special
# ones. The others are the shorter windows that were tried.
BASELINE = Shape(510, 64)
SHAPES = (BASELINE, Shape(256, 64), Shape(128, 64), Shape(64, 32))
# About this many tokens in a batch, so that a small window is not run one at a time.
BATCH_TOKENS = 2048
AGGREGATES = ("max", "top2")
# Dev has 463 injections. A difference of this many of them (1.5 points) is inside the noise of one
# sample, and candidates that close are told apart by what they cost and not by their recall.
NOISE = 7 / 463


def windows_path(shape: Shape, split: str = "dev") -> Path:
    return DATA_DIR / f"windows-{split}-{shape.size}-{shape.overlap}.jsonl"


# -- the model's score of every window


def batch_size_for(shape: Shape) -> int:
    return max(4, BATCH_TOKENS // (shape.size + 2))


def view_for_model(text: str) -> str:
    """What the gateway gives the model: tag characters spelled out, invisible characters taken
    out, NFKC applied (`CompositeScanner.scan`)."""
    return prepare(reveal_tags(text))[0]


def score_windows(engine: WindowedEngine, ids: Sequence[int], shape: Shape) -> list[WindowScore]:
    """The model's score of every window of a text: none skipped and none left out early."""
    spans = split_windows(len(ids), shape.size, shape.overlap)
    step = batch_size_for(shape)
    found: list[WindowScore] = []
    for first in range(0, len(spans), step):
        chunk = spans[first : first + step]
        rows = [[engine.cls_id, *ids[start:end], engine.sep_id] for start, end in chunk]
        scores = engine.infer(rows)
        found += [
            (start, end, round(score, 6)) for (start, end), score in zip(chunk, scores, strict=True)
        ]
    return found


def cache_windows(samples: Sequence[Sample], shape: Shape, out: Path) -> None:
    """Score the windows of every sample and append one line each to `out`. A line that is there
    already is not made again, so an interrupted run goes on where it stopped."""
    spec = SPECS["protectai-deberta-v2"]
    engine = build_engine(
        spec.model_id, spec.revision, spec.labels, shape.size + 2, shape.overlap, 4
    )
    done: set[str] = set()
    if out.is_file():
        done = {json.loads(line)["id"] for line in out.read_text(encoding="utf-8").splitlines()}
    out.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    with out.open("a", encoding="utf-8") as handle:
        for index, sample in enumerate(samples, 1):
            if sample.id in done:
                continue
            ids = engine.tokenize(view_for_model(sample.text))
            scored = score_windows(engine, ids, shape)
            row = {"id": sample.id, "tokens": len(ids), "windows": scored}
            handle.write(json.dumps(row, sort_keys=True) + "\n")
            handle.flush()
            if index % 100 == 0:
                seconds = time.perf_counter() - started
                print(
                    f"  {shape.key}: {index} of {len(samples)} ({seconds:.0f} s)", file=sys.stderr
                )


def read_windows(path: Path) -> dict[str, list[WindowScore]]:
    found: dict[str, list[WindowScore]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        found[row["id"]] = [(int(a), int(b), float(c)) for a, b, c in row["windows"]]
    return found


# -- from windows to one score for the text


def aggregate(windows: Sequence[WindowScore], how: str) -> float:
    """One model score for a text. `max` is the highest window, which is what the gateway used.
    `top2` is the mean of the two highest, so that one odd window is not enough; a text of one
    window has that window's score."""
    scores = sorted((w[2] for w in windows), reverse=True)
    if not scores:
        return 0.0
    if how == "max":
        return scores[0]
    if how == "top2":
        return sum(scores[:2]) / len(scores[:2])
    raise ValueError(f"unknown aggregate {how!r}")


# -- the joins


@dataclass(frozen=True)
class Combiner:
    """A way to make one score of the rules' and the model's. `skips` is true for a rules score
    at which the model is not asked, so that the sweep can say how often it would be."""

    name: str
    join: Join
    skips: Callable[[float], bool] = field(default=lambda rules: False)
    params: Mapping[str, float] = field(default_factory=dict)

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "params": dict(self.params)}


def only_rules(rules: float, model: float | None) -> float:
    return rules


def only_model(rules: float, model: float | None) -> float:
    return 0.0 if model is None else model


def highest(rules: float, model: float | None) -> float:
    return rules if model is None else max(rules, model)


def noisy_or(weight: float) -> Join:
    """The chance that one of two witnesses is right, the model's being worth `weight` of its score:
    `1 - (1 - rules) * (1 - weight * model)`."""

    def join(rules: float, model: float | None) -> float:
        return rules if model is None else 1 - (1 - rules) * (1 - weight * model)

    return join


def scaled_max(weight: float) -> Join:
    def join(rules: float, model: float | None) -> float:
        return rules if model is None else max(rules, weight * model)

    return join


def weighted_sum(rules_weight: float) -> Join:
    """`rules_weight` of the rules and the rest of the model. It can give a text less than the
    rules did, so it cannot ship, and it is measured to say what it would have found."""

    def join(rules: float, model: float | None) -> float:
        return rules if model is None else rules_weight * rules + (1 - rules_weight) * model

    return join


def gated(floor: float, inner: Join) -> tuple[Join, Callable[[float], bool]]:
    """The rules decide alone from `floor` up and the model is not asked; below it `inner` joins
    the two."""

    def join(rules: float, model: float | None) -> float:
        return rules if rules >= floor else inner(rules, model)

    return join, lambda rules: rules >= floor


def when_silent(weight: float) -> tuple[Join, Callable[[float], bool]]:
    """The model counts, at `weight` of its score, only for a text that no rule hit."""

    def join(rules: float, model: float | None) -> float:
        return rules if model is None or rules > 0 else weight * model

    return join, lambda rules: rules > 0


def shipped(floor: float, weight: float) -> Combiner:
    """The join of the gateway, through the function the gateway calls."""

    def join(rules: float, model: float | None) -> float:
        return rules_first(rules, model, floor=floor, weight=weight)

    return Combiner(
        "rules_first", join, lambda rules: rules >= floor, {"floor": floor, "weight": weight}
    )


def never_lowers(join: Join, pairs: Sequence[tuple[float, float]]) -> bool:
    """Whether the join gives every pair of (rules, model) at least the rules' score."""
    return all(join(rules, model) >= rules - 1e-12 for rules, model in pairs)


WEIGHTS = (0.5, 0.6, 0.65, 0.7, 0.75, 0.8, 0.9, 1.0)


def combiners() -> list[Combiner]:
    """Every join the sweep tries. The grid is coarse on purpose: dev has 463 injections and 456
    harmless texts, and a fine grid would be fitted to their noise."""
    found = [Combiner("rules", only_rules), Combiner("model", only_model), Combiner("max", highest)]
    for weight in (0.5, 0.7, 1.0):
        found.append(Combiner("noisy_or", noisy_or(weight), params={"weight": weight}))
        found.append(Combiner("scaled_max", scaled_max(weight), params={"weight": weight}))
        join, skips = when_silent(weight)
        found.append(Combiner("when_silent", join, skips, {"weight": weight}))
    for rules_weight in (0.3, 0.5, 0.7):
        found.append(
            Combiner(
                "weighted_sum", weighted_sum(rules_weight), params={"rules_weight": rules_weight}
            )
        )
    for floor in (0.4, 0.5, 0.6, 0.85):
        for weight in WEIGHTS:
            found.append(shipped(floor, weight))
    for floor in (0.5, 0.6):
        for weight in (0.5, 0.7, 1.0):
            join, skips = gated(floor, scaled_max(weight))
            found.append(
                Combiner("gate_scaled_max", join, skips, {"floor": floor, "weight": weight})
            )
    return found


# -- measuring a candidate


@dataclass(frozen=True)
class Text:
    """A sample with what a join reads of it."""

    sample: Sample
    rules: float
    windows: Mapping[str, Sequence[WindowScore]]


def rules_scores(samples: Sequence[Sample]) -> dict[str, float]:
    scanner = build_scanner(ScannerSettings(classifier="none"))
    return {sample.id: scanner.scan_text(sample.text).score for sample in samples}


def load_texts(data: Dataset, shapes: Sequence[Shape]) -> list[Text]:
    """The texts of dev with their rules' score and the kept windows of every shape."""
    samples = data.split("dev")
    rules = rules_scores(samples)
    caches = {shape.key: read_windows(windows_path(shape)) for shape in shapes}
    return [
        Text(
            sample,
            rules[sample.id],
            {key: cache.get(sample.id, ()) for key, cache in caches.items()},
        )
        for sample in samples
    ]


def candidate_scores(
    texts: Sequence[Text], shape: Shape, how: str, combiner: Combiner
) -> list[float]:
    return [
        combiner.join(text.rules, aggregate(text.windows.get(shape.key, ()), how)) for text in texts
    ]


def measure(texts: Sequence[Text], shape: Shape, how: str, combiner: Combiner) -> dict[str, Any]:
    """Recall at a false positive rate of 5 percent, and what else the candidate does there."""
    scores = candidate_scores(texts, shape, how, combiner)
    labels = [text.sample.label for text in texts]
    point = recall_at_fpr(scores, labels, FPR_BUDGET)
    if point is None:
        raise ValueError("dev needs both injections and harmless texts")
    positives = sum(labels)
    cut = point.threshold

    def share(member: Callable[[Sample], bool]) -> float | None:
        group = [s for s, t in zip(scores, texts, strict=True) if member(t.sample)]
        if not group or cut is None:
            return None
        return round(sum(1 for s in group if s >= cut) / len(group), 4)

    low, high = wilson(round(point.recall * positives), positives) or (0.0, 0.0)
    auc = roc_auc(scores, labels)
    return {
        "shape": shape.key,
        "aggregate": how,
        "combiner": combiner.describe(),
        "recall_at_fpr_5pct": round(point.recall, 4),
        "recall_ci95": [round(low, 4), round(high, 4)],
        "threshold": cut,
        "fpr": round(point.fpr, 4),
        "roc_auc": None if auc is None else round(auc, 4),
        "hard_negatives_flagged": share(lambda s: s.kind == "hard_negative"),
        "recall_documents": share(lambda s: s.kind == "indirect"),
        "recall_public": share(lambda s: s.kind == "public" and s.label == 1),
        "model_asked": round(sum(1 for t in texts if not combiner.skips(t.rules)) / len(texts), 4),
    }


def sweep(texts: Sequence[Text], shapes: Sequence[Shape]) -> list[dict[str, Any]]:
    return [
        measure(texts, shape, how, combiner)
        for shape in shapes
        for how in AGGREGATES
        for combiner in combiners()
    ]


def best_first(rows: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Highest recall first. Of equal recalls the candidate that asks the model least comes first,
    then the one with fewer parameters, then the larger window."""
    return sorted(
        rows,
        key=lambda r: (
            -r["recall_at_fpr_5pct"],
            r["model_asked"],
            len(r["combiner"]["params"]),
            -Shape.parse(r["shape"]).size,
        ),
    )


def eligible(row: Mapping[str, Any]) -> bool:
    """Whether the gateway can run the candidate with the settings it has: the rules-first join
    with its floor at the flag threshold, so that the only number to set is the weight. The other
    joins were tried to see whether anything else did better, and are not what ships."""
    combiner = row["combiner"]
    floor = ScannerSettings().thresholds.suspicious
    return bool(combiner["name"] == "rules_first" and combiner["params"]["floor"] == floor)


def smoothed(row: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> float:
    """The recall of a candidate averaged with that of its two neighbours on the grid of weights,
    for the same shape and aggregate. A weight in the middle of a plateau scores higher than one at
    the edge of a drop, and a drop between two weights is what a threshold crossing a cluster of
    false positives looks like."""
    same = sorted(
        (
            r
            for r in rows
            if eligible(r) and r["shape"] == row["shape"] and r["aggregate"] == row["aggregate"]
        ),
        key=lambda r: r["combiner"]["params"]["weight"],
    )
    at = next(i for i, r in enumerate(same) if r["combiner"] == row["combiner"])
    near = same[max(0, at - 1) : at + 2]
    return sum(r["recall_at_fpr_5pct"] for r in near) / len(near)


def choose(rows: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    """The candidate that ships, by a rule written before the numbers were looked at: of the
    candidates the gateway can run, those whose recall at a false positive rate of 5 percent is
    within the noise of the best (`NOISE`, 7 of dev's 463 injections) are tied. Of the tied the
    larger window wins, because it gives the model fewer windows to be wrong in and fewer false
    positives at the flag threshold; then the aggregate `max`; then the weight with the highest
    smoothed recall."""
    pool = [r for r in rows if eligible(r)]
    if not pool:
        raise ValueError("no candidate can be run by the gateway")
    best = max(r["recall_at_fpr_5pct"] for r in pool)
    tied = [r for r in pool if r["recall_at_fpr_5pct"] >= best - NOISE]
    return max(
        tied,
        key=lambda r: (
            Shape.parse(r["shape"]).size,
            r["aggregate"] == "max",
            smoothed(r, rows),
            r["combiner"]["params"]["weight"],
        ),
    )


def label(row: Mapping[str, Any]) -> str:
    params = ",".join(f"{k}={v}" for k, v in row["combiner"]["params"].items())
    return f"{row['shape']:>7} {row['aggregate']:<4} {row['combiner']['name']}({params})"


def render(rows: Sequence[Mapping[str, Any]], top: int) -> str:
    def cell(value: float | None) -> str:
        return "n/a" if value is None else f"{value:.3f}"

    lines = ["recall@5%    fpr    auc  hardneg   docs  public  asked  candidate"]
    for r in best_first(rows)[:top]:
        lines.append(
            f"{r['recall_at_fpr_5pct']:>9.4f}  {r['fpr']:.3f}  {r['roc_auc']:.3f}  "
            f"{cell(r['hard_negatives_flagged']):>7}  {cell(r['recall_documents']):>5}  "
            f"{cell(r['recall_public']):>6}  {r['model_asked']:>5.2f}  {label(r)}"
        )
    return "\n".join(lines)


# -- why: the model on each kind of text, by shape


GROUPS: dict[str, Callable[[Sample], bool]] = {
    "documents with an attack": lambda s: s.kind == "indirect",
    "harmless documents": lambda s: s.kind == "negative",
    "hard negatives": lambda s: s.kind == "hard_negative",
    "public injections": lambda s: s.kind == "public" and s.label == 1,
    "harmless public prompts": lambda s: s.kind == "public" and s.label == 0,
}


def diagnose(texts: Sequence[Text], shapes: Sequence[Shape]) -> dict[str, Any]:
    """For each kind of text, the share the model alone scores at 0.5 or more, and at 0.95 or more,
    by the shape of the windows, next to the rules' share at 0.5. A kind with no text has no
    share."""

    def share(scores: Sequence[float], at: float) -> float | None:
        if not scores:
            return None
        return round(sum(1 for s in scores if s >= at) / len(scores), 4)

    found: dict[str, Any] = {}
    for name, member in GROUPS.items():
        group = [t for t in texts if member(t.sample)]
        by_shape = {}
        for shape in shapes:
            scores = [aggregate(t.windows.get(shape.key, ()), "max") for t in group]
            by_shape[shape.key] = {"at_0.5": share(scores, 0.5), "at_0.95": share(scores, 0.95)}
        found[name] = {
            "n": len(group),
            "rules_at_0.5": share([t.rules for t in group], 0.5),
            "model": by_shape,
        }
    return found


# -- how much of it is luck


def bootstrap(
    texts: Sequence[Text],
    candidates: Mapping[str, tuple[Shape, str, Combiner]],
    *,
    resamples: int = 200,
    seed: int = 792,
) -> dict[str, Any]:
    """Resample the carriers of dev with replacement, `resamples` times, and measure each candidate
    on each resample. A carrier and every attack put in it go together, as in the split. Gives the
    mean and the 95 percent range of recall at a false positive rate of 5 percent, and of the
    difference from the first candidate, which is the one to beat."""
    by_carrier: dict[str, list[int]] = defaultdict(list)
    for index, text in enumerate(texts):
        by_carrier[text.sample.carrier].append(index)
    carriers = sorted(by_carrier)
    scored = {
        name: candidate_scores(texts, shape, how, combiner)
        for name, (shape, how, combiner) in candidates.items()
    }
    labels = [text.sample.label for text in texts]
    chosen = random.Random(seed)  # noqa: S311 - a bootstrap is not a secret
    recalls: dict[str, list[float]] = {name: [] for name in candidates}
    for _ in range(resamples):
        picked = [
            i for carrier in chosen.choices(carriers, k=len(carriers)) for i in by_carrier[carrier]
        ]
        for name, scores in scored.items():
            point = recall_at_fpr(
                [scores[i] for i in picked], [labels[i] for i in picked], FPR_BUDGET
            )
            recalls[name].append(0.0 if point is None else point.recall)
    reference = next(iter(candidates))

    def summary(values: Sequence[float]) -> dict[str, float]:
        ordered = sorted(values)
        return {
            "mean": round(sum(ordered) / len(ordered), 4),
            "low": round(ordered[int(0.025 * len(ordered))], 4),
            "high": round(ordered[min(len(ordered) - 1, int(0.975 * len(ordered)))], 4),
        }

    return {
        "resamples": resamples,
        "seed": seed,
        "reference": reference,
        "recall": {name: summary(values) for name, values in recalls.items()},
        "gain_over_reference": {
            name: summary([a - b for a, b in zip(values, recalls[reference], strict=True)])
            for name, values in recalls.items()
            if name != reference
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Try ways to join the rules and the model on dev")
    commands = parser.add_subparsers(dest="command", required=True)
    cache = commands.add_parser("windows", help="score every window of dev and keep the scores")
    cache.add_argument("--shape", required=True, help="size/overlap, for example 128/64")
    cache.add_argument("--split", default="dev")
    try_all = commands.add_parser("sweep", help="try the joins on the kept windows")
    try_all.add_argument("--shapes", nargs="*", default=[s.key for s in SHAPES])
    try_all.add_argument("--top", type=int, default=25)
    try_all.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.command == "windows" and args.split != "dev":
        print("the windows are scored on dev only: test is for report.py", file=sys.stderr)
        return 2
    data = build(download=True)
    if args.command == "windows":
        shape = Shape.parse(args.shape)
        cache_windows(data.split("dev"), shape, windows_path(shape))
        return 0

    shapes = [Shape.parse(key) for key in args.shapes]
    texts = load_texts(data, shapes)
    rows = sweep(texts, shapes)
    print(render(rows, args.top))
    chosen = choose(rows)
    print(f"\nchosen: {label(chosen)}  recall {chosen['recall_at_fpr_5pct']}")
    if args.out:
        floor, weight = (
            chosen["combiner"]["params"]["floor"],
            chosen["combiner"]["params"]["weight"],
        )
        shape = Shape.parse(chosen["shape"])
        compared: dict[str, tuple[Shape, str, Combiner]] = {
            "rules": (shape, chosen["aggregate"], Combiner("rules", only_rules)),
            "chosen": (shape, chosen["aggregate"], shipped(floor, weight)),
        }
        if BASELINE in shapes:
            compared["phase 7"] = (BASELINE, "max", Combiner("max", highest))
        document = {
            "split": "dev",
            "date": datetime.now(UTC).date().isoformat(),
            "n": len(texts),
            "injections": sum(t.sample.label for t in texts),
            "candidates": len(rows),
            "noise": round(NOISE, 4),
            "selection": (
                "of the candidates the gateway can run (the rules-first join with its floor at the "
                "flag threshold), those within the noise of the best recall at a false positive "
                "rate of 5 percent are tied; of the tied the larger window, then the aggregate "
                "max, then the weight with the highest smoothed recall"
            ),
            "chosen": chosen,
            "bootstrap": bootstrap(texts, compared),
            "diagnosis": diagnose(texts, shapes),
            "rows": best_first(rows),
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
