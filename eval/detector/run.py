"""Run the detector on a split of the dataset and say what it gets right and wrong (KS-707).

    python -m eval.detector.run --config rules --split dev
    python -m eval.detector.run --config combined --split test --out result.json
    python -m eval.detector.run --config rules --split test --limit 200      # the nightly run

`--config` is `rules` (the seven rules of ADR-0011), `classifier` (the model alone, which is asked
about every text) or `combined` (the rules and the model joined the way the gateway joins them: by
default the rules first and then the model, `scanner.join`). `--join`, `--window-tokens`,
`--window-overlap` and `--model-weight` run another setting of the scanner; the report uses them
to measure what Phase 7 shipped next to what runs now. The model needs the extra
`keystone[scanner]`. The rules need nothing.

For every text the run takes the score of the scanner and the time the scan took, one text at a
time so that the timings mean something. Then it computes, for each config:

- precision, recall, F1 and the false positive rate at the configured thresholds: `flag` is
  `scanner.thresholds.suspicious`, where an output is annotated, and `taint` is
  `scanner.thresholds.injection`, where a session is tainted;
- ROC AUC, average precision, and recall at a false positive rate of 5 percent or less;
- the false positive rate on the hard negatives alone, with its 95 percent interval, because a
  detector that flags every how-to guide is one that people turn off;
- the same for the public prompts and for the synthetic documents apart, since the second kind was
  written with the first kind's rules in view and the first was not;
- recall by the family of attack, by where it was put and by whether it was hidden;
- p50 and p95 of the time of a scan, for texts under 500 tokens, from 500 to 2,000 and over 2,000.

The model is given as long as it needs (`--timeout-ms`, 10 s), so that the numbers say what it can
do. The gateway waits 300 ms by default and then goes on with the rules, so a `combined` run also
reports `combined_300ms`, computed from the measured time of each scan: a text whose scan took more
than 300 ms is scored by its rules alone. That row is derived from the timings and not a second run.
With the rules-first join a text the rules flag is not given to the model, so the model has no score
for it and `classifier` is not asked of that run: the model alone is a run with `--join max`.

A run on `test` is logged in `eval/results/test-runs.jsonl`, every time: the test split is for the
numbers that are published, thresholds are tuned on `dev` (`tune.py`), and the log is how anyone
can see how often `test` was looked at.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import platform
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.detector.datasets import REPO, Dataset, Sample, build, summary
from eval.detector.metrics import (
    Confusion,
    average_precision,
    confusion,
    latency_by_bucket,
    recall_at_fpr,
    roc_auc,
    wilson,
)
from keystone.core.types import ToolRef
from keystone.defense.classifier import load_classifier
from keystone.defense.rules import default_rules
from keystone.defense.scanner import SKIPPED, CompositeScanner, build_scanner
from keystone.settings import ScannerSettings

CONFIGS = ("rules", "classifier", "combined")
RESULTS = REPO / "eval" / "results"
RUN_LOG = RESULTS / "test-runs.jsonl"
DEFAULT_TIMEOUT_MS = 10_000
# What the gateway waits for the model by default (`scanner.classifier_timeout_ms`).
GATEWAY_TIMEOUT_MS = 300
WARMUP_TEXTS = 3
FPR_BUDGET = 0.05

TOOL = ToolRef(
    name="eval__scan",
    upstream_id="eval",
    upstream_tool_name="scan",
    tenant_id="acme",
    description="",
    input_schema={},
    description_hash="",
    schema_hash="",
)


@dataclass(frozen=True)
class Scored:
    """One text and what the scanner made of it."""

    sample: Sample
    rules: float
    classifier: float | None
    combined: float
    rules_ms: float
    # The time of a scan with the model, or None for a run on the rules alone.
    scan_ms: float | None = None
    model: str | None = None


def pick_subset(samples: Sequence[Sample], limit: int | None) -> list[Sample]:
    """`limit` samples that do not depend on the order of the list: the first by the hash of the id.
    The mix of kinds stays about what it was, and a smaller run is a run of the same samples."""
    ordered = sorted(samples, key=lambda s: hashlib.sha256(s.id.encode()).hexdigest())
    return ordered[:limit] if limit else ordered


def score_rules(samples: Sequence[Sample], settings: ScannerSettings) -> list[Scored]:
    """The rules alone: no model, no event loop."""
    scanner = build_scanner(settings)
    found = []
    for sample in samples:
        started = time.perf_counter()
        details = scanner.scan_text(sample.text)
        elapsed = (time.perf_counter() - started) * 1000
        found.append(Scored(sample, details.score, None, details.score, elapsed))
    return found


async def score_with_model(
    samples: Sequence[Sample],
    settings: ScannerSettings,
    *,
    progress: Callable[[int, int], None] | None = None,
) -> list[Scored]:
    """The rules and the model, the way the gateway runs them, one text at a time."""
    classifier = load_classifier(settings)
    if classifier is None:
        raise RuntimeError(
            "the classifier is not available: install the extra (uv sync --extra scanner), "
            "or run the rules config"
        )
    warm = getattr(classifier, "warm", None)
    if warm is not None:
        await warm()
    scanner = CompositeScanner(default_rules(settings.allowed_domains), classifier, settings)
    for sample in samples[:WARMUP_TEXTS]:  # the first scans of a process are slower
        await scanner.scan(sample.text, tool=TOOL)
    rules_only = build_scanner(settings)
    found = []
    for index, sample in enumerate(samples):
        started = time.perf_counter()
        rules_only.scan_text(sample.text)
        rules_ms = (time.perf_counter() - started) * 1000
        details = await scanner.scan(sample.text, tool=TOOL)
        found.append(
            Scored(
                sample,
                getattr(details, "rule_score", details.score),
                getattr(details, "classifier_score", None),
                details.score,
                rules_ms,
                details.latency_ms,
                details.model,
            )
        )
        if progress is not None:
            progress(index + 1, len(samples))
    return found


# -- the numbers


def _rate(count: int, total: int) -> dict[str, Any]:
    interval = wilson(count, total)
    return {
        "count": count,
        "of": total,
        "rate": count / total if total else None,
        "ci95": [round(interval[0], 4), round(interval[1], 4)] if interval else None,
    }


def _point(
    items: Sequence[Scored], pick: Callable[[Scored], float], threshold: float
) -> dict[str, Any]:
    scores = [pick(i) for i in items]
    labels = [i.sample.label for i in items]
    counts: Confusion = confusion(scores, labels, threshold)
    return {
        "threshold": threshold,
        "tp": counts.tp,
        "fp": counts.fp,
        "tn": counts.tn,
        "fn": counts.fn,
        "precision": round(counts.precision, 4),
        "recall": round(counts.recall, 4),
        "f1": round(counts.f1, 4),
        "fpr": round(counts.fpr, 4),
    }


def _ranking(items: Sequence[Scored], pick: Callable[[Scored], float]) -> dict[str, Any]:
    scores = [pick(i) for i in items]
    labels = [i.sample.label for i in items]
    auc = roc_auc(scores, labels)
    average = average_precision(scores, labels)
    operating = recall_at_fpr(scores, labels, FPR_BUDGET)
    positives = sum(labels)
    return {
        "roc_auc": None if auc is None else round(auc, 4),
        "average_precision": None if average is None else round(average, 4),
        "recall_at_fpr_5pct": None
        if operating is None
        else {
            "recall": round(operating.recall, 4),
            "recall_ci95": [
                round(x, 4) for x in (wilson(round(operating.recall * positives), positives) or ())
            ],
            "threshold": operating.threshold,
            "fpr": round(operating.fpr, 4),
        },
    }


def _recall_by(
    items: Sequence[Scored], pick: Callable[[Scored], float], threshold: float, key: str
) -> dict[str, Any]:
    groups: dict[str, list[Scored]] = {}
    for item in items:
        if item.sample.label == 1 and item.sample.kind == "indirect":
            groups.setdefault(item.sample.meta[key], []).append(item)
    return {
        name: _rate(sum(1 for i in group if pick(i) >= threshold), len(group))
        for name, group in sorted(groups.items())
    }


def config_metrics(
    items: Sequence[Scored],
    pick: Callable[[Scored], float],
    timing: Callable[[Scored], float | None],
    flag: float,
    taint: float,
) -> dict[str, Any]:
    """Everything a report says about one config."""
    hard = [i for i in items if i.sample.kind == "hard_negative"]
    operating = recall_at_fpr([pick(i) for i in items], [i.sample.label for i in items], FPR_BUDGET)
    at_budget = operating.threshold if operating and operating.threshold is not None else None
    subsets = {
        "public": [i for i in items if i.sample.kind == "public"],
        "documents": [i for i in items if i.sample.kind != "public"],
    }
    negatives_by_kind: dict[str, Any] = {}
    for kind in ("negative", "hard_negative"):
        group = [i for i in items if i.sample.kind == kind]
        negatives_by_kind[kind] = _rate(sum(1 for i in group if pick(i) >= flag), len(group))
    public_negatives = [i for i in subsets["public"] if i.sample.label == 0]
    negatives_by_kind["public"] = _rate(
        sum(1 for i in public_negatives if pick(i) >= flag), len(public_negatives)
    )
    timings = [(i.sample.tokens, ms) for i in items if (ms := timing(i)) is not None]
    return {
        "flag": _point(items, pick, flag),
        "taint": _point(items, pick, taint),
        **_ranking(items, pick),
        "hard_negatives": {
            "flag": _rate(sum(1 for i in hard if pick(i) >= flag), len(hard)),
            "taint": _rate(sum(1 for i in hard if pick(i) >= taint), len(hard)),
            "at_5pct_threshold": None
            if at_budget is None
            else _rate(sum(1 for i in hard if pick(i) >= at_budget), len(hard)),
            "by_family": {
                family: _rate(
                    sum(1 for i in hard if i.sample.meta["family"] == family and pick(i) >= flag),
                    sum(1 for i in hard if i.sample.meta["family"] == family),
                )
                for family in sorted({i.sample.meta["family"] for i in hard})
            },
        },
        "negatives_by_kind": negatives_by_kind,
        "subsets": {
            name: {
                "n": len(group),
                "injections": sum(i.sample.label for i in group),
                "flag": _point(group, pick, flag) if group else None,
                **(_ranking(group, pick) if group else {}),
            }
            for name, group in subsets.items()
        },
        "recall_by_family": _recall_by(items, pick, flag, "family"),
        "recall_by_template": _recall_by(items, pick, flag, "template"),
        "recall_by_hidden": _recall_by(items, pick, flag, "hidden"),
        "recall_by_position": _recall_by(items, pick, flag, "position"),
        "latency": latency_by_bucket(timings),
    }


def evaluate(
    scored: Sequence[Scored],
    configs: Sequence[str],
    flag: float,
    taint: float,
    prefix: str = "",
) -> dict[str, Any]:
    """The metrics of each config in `configs`, for the scored texts, under names that start with
    `prefix` (the report keeps a second run of the scanner beside the first, as `previous_`)."""
    out: dict[str, Any] = {}
    if "rules" in configs:
        out[f"{prefix}rules"] = config_metrics(
            scored, lambda i: i.rules, lambda i: i.rules_ms, flag, taint
        )
    # A text of a run with a model: the model answered, was left out for being slow or failing, or
    # was not asked because the rules had flagged the text. The model alone has a score for the
    # first kind only, and the joined score is there for all of them.
    run_with_model = [i for i in scored if i.model is not None]
    answered = [i for i in run_with_model if i.classifier is not None]
    if "classifier" in configs:
        out[f"{prefix}classifier"] = config_metrics(
            answered, lambda i: i.classifier or 0.0, lambda i: i.scan_ms, flag, taint
        )
    if "combined" in configs:
        out[f"{prefix}combined"] = config_metrics(
            run_with_model, lambda i: i.combined, lambda i: i.scan_ms, flag, taint
        )
        # What the gateway does with a 300 ms wait: a text whose scan took longer is scored by the
        # rules alone. Derived from the measured time of each scan.
        waiting = config_metrics(
            run_with_model,
            lambda i: i.combined if (i.scan_ms or 0.0) <= GATEWAY_TIMEOUT_MS else i.rules,
            lambda i: i.scan_ms,
            flag,
            taint,
        )
        waiting["fell_back_to_rules"] = _rate(
            sum(1 for i in run_with_model if (i.scan_ms or 0.0) > GATEWAY_TIMEOUT_MS),
            len(run_with_model),
        )
        out[f"{prefix}combined_300ms"] = waiting
    return out


def describe_samples(samples: Sequence[Sample]) -> dict[str, Any]:
    kinds = Counter((s.kind, s.label) for s in samples)
    return {
        "n": len(samples),
        "injections": sum(s.label for s in samples),
        "carriers": len({s.carrier for s in samples}),
        "kinds": {f"{kind}/{label}": n for (kind, label), n in sorted(kinds.items())},
    }


# -- running and logging


def git_state() -> dict[str, Any]:
    def run(*args: str) -> str:
        return subprocess.run(  # noqa: S603 - fixed arguments
            ["git", "-C", str(REPO), *args],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()

    return {"commit": run("rev-parse", "HEAD"), "dirty": bool(run("status", "--porcelain"))}


def machine() -> dict[str, Any]:
    import os

    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
    }


def plan(config: str, settings: ScannerSettings) -> tuple[tuple[str, ...], ScannerSettings]:
    """The configs to measure and the settings to score them with, for the name of a config on a
    command line. `classifier` is the model alone, so the scanner is set to ask it about every text
    (`join: max`); `combined` is the scanner as it is set."""
    if config == "rules":
        return ("rules",), settings
    if config == "classifier":
        return ("rules", "classifier"), settings.model_copy(update={"join": "max"})
    return ("rules", "combined"), settings


def score_split(
    data: Dataset,
    split: str,
    configs: Sequence[str],
    *,
    limit: int | None = None,
    settings: ScannerSettings | None = None,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    progress: Callable[[int, int], None] | None = None,
) -> list[Scored]:
    """Score a split. One pass with the model serves both `classifier` and `combined` when the
    scanner asks the model about every text (`join: max`); with the rules-first join it does not
    ask about a text the rules flag, and the model alone cannot be measured in that pass."""
    base = settings or ScannerSettings()
    if "classifier" in configs and base.join != "max":
        raise ValueError(
            "the model alone needs `join: max`: with `rules_first` it is not asked about a text "
            "the rules flag, so it has no score for it"
        )
    samples = pick_subset(data.split(split), limit)
    if any(c in ("classifier", "combined") for c in configs):
        modelled = base.model_copy(update={"classifier_timeout_ms": timeout_ms})
        return asyncio.run(score_with_model(samples, modelled, progress=progress))
    return score_rules(samples, base.model_copy(update={"classifier": "none"}))


def scanner_facts(settings: ScannerSettings) -> dict[str, Any]:
    """The settings of the scanner that decide what a model run measures."""
    return {
        "join": settings.join,
        "model_weight": settings.model_weight,
        "window_tokens": settings.window_tokens,
        "window_overlap": settings.window_overlap,
    }


def assemble(
    data: Dataset,
    split: str,
    configs: Sequence[str],
    scored: Sequence[Scored],
    base: ScannerSettings,
    limit: int | None,
    timeout_ms: int,
) -> dict[str, Any]:
    """The metrics of the configs for scored texts, with the facts a report needs."""
    flag, taint = base.thresholds.suspicious, base.thresholds.injection
    modelled = any(c != "rules" for c in configs)
    return {
        "split": split,
        "limit": limit,
        "thresholds": {"flag": flag, "taint": taint},
        "samples": describe_samples([s.sample for s in scored]),
        "configs": evaluate(scored, configs, flag, taint),
        "model_failures": sum(1 for s in scored if s.model in ("timeout", "error")),
        "model_skipped": sum(1 for s in scored if s.model == SKIPPED),
        "notes": list(data.notes),
        "classifier": base.classifier if modelled else None,
        "timeout_ms": timeout_ms if modelled else None,
        "scanner": scanner_facts(base) if modelled else None,
    }


def run_split(
    data: Dataset,
    split: str,
    configs: Sequence[str],
    *,
    limit: int | None = None,
    settings: ScannerSettings | None = None,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Score a split with the configs and compute the metrics."""
    base = settings or ScannerSettings()
    scored = score_split(
        data, split, configs, limit=limit, settings=base, timeout_ms=timeout_ms, progress=progress
    )
    return assemble(data, split, configs, scored, base, limit, timeout_ms)


def write_scores(scored: Sequence[Scored], path: Path) -> None:
    """One line for each text with its scores and timings, so that a later command (the tuning)
    need not run the model again."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as out:
        for item in scored:
            row = {
                "id": item.sample.id,
                "rules": item.rules,
                "classifier": item.classifier,
                "combined": item.combined,
                "rules_ms": item.rules_ms,
                "scan_ms": item.scan_ms,
                "model": item.model,
            }
            out.write(json.dumps(row, sort_keys=True) + "\n")


def read_scores(path: Path, data: Dataset) -> list[Scored]:
    """The scores `write_scores` wrote, joined to the samples of `data` by id."""
    by_id = {s.id: s for s in data.samples}
    found = []
    for line in path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        found.append(
            Scored(
                by_id[row["id"]],
                row["rules"],
                row["classifier"],
                row["combined"],
                row["rules_ms"],
                row["scan_ms"],
                row["model"],
            )
        )
    return found


def log_test_run(result: Mapping[str, Any], path: Path | None = None, note: str = "") -> None:
    """One line for each run on the test split, so that how often it was looked at is on record."""
    path = path or RUN_LOG
    headline = {
        name: {
            "recall_at_fpr_5pct": config.get("recall_at_fpr_5pct"),
            "hard_negative_fpr_flag": config["hard_negatives"]["flag"]["rate"],
        }
        for name, config in result["configs"].items()
    }
    line = {
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        **git_state(),
        "thresholds": result["thresholds"],
        "limit": result["limit"],
        "n": result["samples"]["n"],
        "configs": sorted(result["configs"]),
        "headline": headline,
        # How the scanner was set, so that a line says what was measured (KS-792).
        **({"scanner": result["scanner"]} if result.get("scanner") else {}),
        **(
            {"previous_scanner": result["previous_scanner"]}
            if result.get("previous_scanner")
            else {}
        ),
        **({"note": note} if note else {}),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as log:
        log.write(json.dumps(line, sort_keys=True) + "\n")


def one_line(result: Mapping[str, Any]) -> str:
    rows = []
    for name, config in result["configs"].items():
        point = config.get("recall_at_fpr_5pct") or {}
        hard = config["hard_negatives"]["flag"]
        rows.append(
            f"{name}: auc {config['roc_auc']}, recall at 5% fpr {point.get('recall')}, "
            f"flag f1 {config['flag']['f1']}, hard-negative fpr {hard['count']}/{hard['of']}"
        )
    return "; ".join(rows)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the detector on a split of the dataset")
    parser.add_argument("--config", choices=CONFIGS, required=True)
    parser.add_argument("--split", choices=("dev", "test"), required=True)
    parser.add_argument("--limit", type=int, default=None, help="only this many samples")
    parser.add_argument("--out", type=Path, default=None, help="write the JSON here")
    parser.add_argument("--offline", action="store_true", help="do not download the public parts")
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    parser.add_argument("--join", choices=("rules_first", "max"), default=None)
    parser.add_argument("--model-weight", type=float, default=None)
    parser.add_argument("--window-tokens", type=int, default=None)
    parser.add_argument("--window-overlap", type=int, default=None)
    parser.add_argument("--no-log", action="store_true", help="do not log a run on test")
    parser.add_argument("--note", default="", help="why a run on test was made, for its log line")
    parser.add_argument("--summary", action="store_true", help="print one line and not the JSON")
    parser.add_argument("--scores", type=Path, default=None, help="also write each text's scores")
    parser.add_argument(
        "--fail-under-auc",
        type=float,
        default=None,
        help="exit 1 when the ROC AUC of the first config is under this (a guard, not a result)",
    )
    args = parser.parse_args(argv)

    data = build(download=not args.offline)
    print(summary(data), file=sys.stderr)

    def progress(done: int, total: int) -> None:
        if done % 100 == 0 or done == total:
            print(f"  scored {done} of {total}", file=sys.stderr, flush=True)

    given = {
        key: value
        for key, value in (
            ("join", args.join),
            ("model_weight", args.model_weight),
            ("window_tokens", args.window_tokens),
            ("window_overlap", args.window_overlap),
        )
        if value is not None
    }
    configs, base = plan(args.config, ScannerSettings.model_validate(given))
    scored = score_split(
        data,
        args.split,
        configs,
        limit=args.limit,
        settings=base,
        timeout_ms=args.timeout_ms,
        progress=progress,
    )
    if args.scores:
        write_scores(scored, args.scores)
    result = assemble(data, args.split, configs, scored, base, args.limit, args.timeout_ms)
    result["asked"] = args.config
    if args.split == "test" and not args.no_log:
        log_test_run(result, note=args.note)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(one_line(result) if args.summary else text)
    if args.fail_under_auc is not None:
        first = next(iter(result["configs"].values()))
        auc = first["roc_auc"]
        if auc is None or auc < args.fail_under_auc:
            print(
                f"the ROC AUC is {auc}, under the guard of {args.fail_under_auc}", file=sys.stderr
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
