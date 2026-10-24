"""Choose the thresholds on the dev split (KS-707).

    python -m eval.detector.tune                 # the combined score, on dev
    python -m eval.detector.tune --config rules

The gateway has two thresholds (`scanner.thresholds`). At `suspicious` an output is annotated,
redacted or withheld, by the risk of its tool. At `injection` a session is tainted. They are chosen
here, on `dev`, and the test split is never read (the command refuses to):

- `suspicious` is the threshold with the highest F0.5 on dev over a grid in steps of 0.05, which
  counts precision twice as much as recall. Of equal scores the higher threshold is taken, the one
  that flags less. A miss is not the end of an attack, since the Rule of Two asks a person before
  a session that read untrusted data acts outside; a false positive has no such second layer and
  costs an agent a tool, or a person an approval. F1 is in the table too. On the dev split its
  highest point is below 0.45, where texts that only the weak rule `tool_directive` (0.4) flags
  start to count, and it moves the false positive rate on hard negatives by 18 points for 7 points
  of recall. I looked at F1 first and chose F0.5 after seeing that, and the table shows both.
- `injection` is the lowest threshold from `suspicious` up at which the precision on dev is at
  least 0.95: a session is tainted for good, so a taint should be right nineteen times in twenty.
  When no threshold gets there the answer is "none" and the configured value stays.

What it prints is a table of the grid and the pair it recommends. Whether the defaults in
`settings.py` change is a decision for the person who reads it, because other things stand on them:
the poisoned email of the demo scores 0.88 from the rules alone and must stay an `injection`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.detector.datasets import build
from eval.detector.metrics import confusion
from eval.detector.run import RESULTS, Scored, plan, read_scores, score_split, write_scores
from keystone.settings import ScannerSettings

GRID = [round(0.05 * step, 2) for step in range(4, 20)]  # 0.20 to 0.95
PRECISION_FLOOR = 0.95
BETA = 0.5


def sweep(scored: Sequence[Scored], config: str) -> list[dict[str, Any]]:
    """What each threshold of the grid does on these texts."""

    def pick(item: Scored) -> float:
        return {"rules": item.rules, "classifier": item.classifier or 0.0}.get(
            config, item.combined
        )

    # The model alone counts the texts it scored. The joined score counts the texts of a run with a
    # model, and that includes the texts the rules flagged and the model was not asked about.
    if config == "rules":
        items = list(scored)
    elif config == "classifier":
        items = [i for i in scored if i.classifier is not None]
    else:
        items = [i for i in scored if i.model is not None]
    scores = [pick(i) for i in items]
    labels = [i.sample.label for i in items]
    hard = [pick(i) for i in items if i.sample.kind == "hard_negative"]

    def hard_rate(threshold: float) -> float | None:
        """None when there are no hard negatives among these texts: nothing was measured."""
        if not hard:
            return None
        return round(sum(1 for score in hard if score >= threshold) / len(hard), 4)

    rows = []
    for threshold in GRID:
        counts = confusion(scores, labels, threshold)
        rows.append(
            {
                "threshold": threshold,
                "precision": round(counts.precision, 4),
                "recall": round(counts.recall, 4),
                "f1": round(counts.f1, 4),
                "f0_5": round(counts.f_beta(BETA), 4),
                "fpr": round(counts.fpr, 4),
                "hard_negative_fpr": hard_rate(threshold),
            }
        )
    return rows


def recommend(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    best = max(rows, key=lambda r: (r["f0_5"], r["threshold"]))
    taint = next(
        (
            r
            for r in rows
            if r["threshold"] >= best["threshold"] and r["precision"] >= PRECISION_FLOOR
        ),
        None,
    )
    return {
        "suspicious": best["threshold"],
        "injection": None if taint is None else taint["threshold"],
        "precision_floor": PRECISION_FLOOR,
    }


def render(rows: Sequence[dict[str, Any]], chosen: dict[str, Any]) -> str:
    lines = ["threshold  precision  recall     f1   f0.5    fpr  hard-negative fpr"]
    for r in rows:
        mark = " <- suspicious" if r["threshold"] == chosen["suspicious"] else ""
        mark += " <- injection" if r["threshold"] == chosen["injection"] else ""
        hard = "n/a" if r["hard_negative_fpr"] is None else f"{r['hard_negative_fpr']:.4f}"
        first = f"{r['threshold']:>9.2f}  {r['precision']:>9.4f}  {r['recall']:>6.4f}"
        second = f"{r['f1']:>5.4f}  {r['f0_5']:>5.4f}  {r['fpr']:>5.4f}  {hard:>6}"
        lines.append(f"{first}  {second}{mark}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Choose the thresholds on the dev split")
    parser.add_argument("--config", choices=("rules", "classifier", "combined"), default="combined")
    parser.add_argument("--split", default="dev")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--scores",
        type=Path,
        default=None,
        help="read the scores of a run from here if the file exists, else write them there",
    )
    args = parser.parse_args(argv)
    if args.split != "dev":
        print("thresholds are tuned on dev only", file=sys.stderr)
        return 2

    data = build(download=not args.offline)
    configs, settings = plan(args.config, ScannerSettings())
    if args.scores and args.scores.is_file():
        scored = read_scores(args.scores, data)
    else:
        scored = score_split(data, "dev", configs, settings=settings)
        if args.scores:
            write_scores(scored, args.scores)
    rows = sweep(scored, args.config)
    chosen = recommend(rows)
    print(render(rows, chosen))
    print(f"\nrecommended: suspicious {chosen['suspicious']}, injection {chosen['injection']}")
    print(f"configured:  {ScannerSettings().thresholds.model_dump()}")
    result = {
        "split": "dev",
        "config": args.config,
        "date": datetime.now(UTC).date().isoformat(),
        "n": len(scored),
        "notes": list(data.notes),
        "grid": rows,
        "recommended": chosen,
        "criteria": {
            "suspicious": f"highest F{BETA} on dev, ties to the higher threshold",
            "injection": f"lowest threshold from suspicious up with precision of {PRECISION_FLOOR}",
        },
        "current": ScannerSettings().thresholds.model_dump(),
    }
    target = args.out or RESULTS / f"tuning-{result['date']}-{args.config}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
