"""Write the report of the detector evaluation (KS-707).

    python -m eval.detector.report                # all three configs on the test split
    python -m eval.detector.report --limit 200    # a sample, for a quick look (nothing written)

It scores the test split once with the rules and the model, computes the metrics of the three
configs (`rules`, `classifier`, `combined`), and writes two things: the file
`eval/results/detector-<date>.json` with every number, and the detector section of
`docs/results.md` with the ones a reader needs.
Both say the date, the commit the code was at and whether the tree was clean, the revision of every
public dataset, the thresholds and the machine, because a number without those is not a result.

Nothing here invents a figure. A cell is filled from the JSON, and where the JSON has none (a bucket
with no text in it, a config that was not run) the cell says "not measured".
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.detector import run
from eval.detector.datasets import MANIFEST, REPO, Dataset, build, load_manifest
from eval.detector.run import RESULTS, git_state, log_test_run, machine, run_split
from keystone.settings import ScannerSettings

RESULTS_DOC = REPO / "docs" / "results.md"
START = "<!-- detector:start -->"
END = "<!-- detector:end -->"
NAMES = {
    "rules": "Rules",
    "classifier": "Model",
    "combined": "Rules and model",
    "combined_300ms": "Rules and model, 300 ms wait",
}
MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
MODEL_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
NOT = "not measured"


def num(value: float | None, places: int = 2) -> str:
    return NOT if value is None else f"{value:.{places}f}"


def rate(cell: Mapping[str, Any] | None, places: int = 2) -> str:
    """`0.29 (24 of 84, 95% 0.20 to 0.39)` from a rate cell of the JSON."""
    if not cell or cell.get("rate") is None:
        return NOT
    low, high = cell["ci95"]
    return (
        f"{cell['rate']:.{places}f} ({cell['count']} of {cell['of']}, 95% {low:.2f} to {high:.2f})"
    )


def recall_cell(point: Mapping[str, Any] | None) -> str:
    if not point:
        return NOT
    low, high = point["recall_ci95"]
    return f"{point['recall']:.2f} (95% {low:.2f} to {high:.2f}) at {num(point['threshold'])}"


def table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def configs_of(document: Mapping[str, Any]) -> dict[str, Any]:
    found: dict[str, Any] = document["result"]["configs"]
    return found


def render_section(document: Mapping[str, Any]) -> str:
    """The detector section of docs/results.md, from a report document."""
    result = document["result"]
    configs = configs_of(document)
    shown = [name for name in ("rules", "classifier", "combined") if name in configs]
    flag, taint = result["thresholds"]["flag"], result["thresholds"]["taint"]
    samples = result["samples"]
    commit = document["commit"][:12] + (" plus uncommitted changes" if document["dirty"] else "")
    sources = document["dataset"]["sources"]
    out = [
        "## Detector",
        "",
        f"Measured on {document['date']} at commit `{commit}`, on "
        f"{document['machine']['platform']} ({document['machine']['cpus']} CPUs, "
        f"Python {document['machine']['python']}), by `python -m eval.detector.report`. Every "
        f"number below is in `eval/results/detector-{document['date']}.json`.",
        "",
        f"The test split has {samples['n']} texts from {samples['carriers']} carriers, "
        f"{samples['injections']} of them injections. Thresholds were tuned on the dev split "
        f"only: a text is flagged at {flag} and a session is tainted at {taint}. "
        "The test split was scored "
        f"{document['test_runs']} time(s) before this report; every run is in "
        "`eval/results/test-runs.jsonl`.",
        "",
        "The data (`eval/DATASETS.md` has sources and licenses):",
        "",
        "- **Public prompts**: "
        f"`{sources['public']['dataset']}`, {document['dataset']['counts'].get('public', 0)} "
        "prompts of both labels, in English and German. They are direct requests to a model "
        "and not documents.",
        "- **Documents**: emails, pages and files, harmless as they are and with one of 12 attacks "
        "from `examples/fixtures/injections/templates.yaml` put at the start, middle or end, a "
        "quarter of them hidden with invisible characters. "
        f"{document['dataset']['counts'].get('synthetic', 0)} texts are generated from the "
        f"fixtures of this repository, and {document['dataset']['counts'].get('wikitext', 0)} are "
        f"built on articles of `{sources['wikitext']['dataset']}`.",
        "- **Hard negatives**: 150 harmless texts that sound like instructions (how-to guides, "
        "recipes, business mail, and security articles that quote attacks).",
    ]
    for note in document["dataset"]["notes"]:
        out += ["", f"**Not complete**: {note}."]
    out += ["", "### How good the scores are", ""]
    rows = []
    for name in shown:
        c = configs[name]
        rows.append(
            [
                NAMES[name],
                recall_cell(c["recall_at_fpr_5pct"]),
                num(c["roc_auc"], 3),
                num(c["average_precision"], 3),
            ]
        )
    out += [
        table(
            [
                "Config",
                "Recall at a false positive rate of 5% or less",
                "ROC AUC",
                "Average precision",
            ],
            rows,
        ),
        "",
        "Recall at a fixed false positive rate does not depend on the thresholds, so it is the "
        "number to compare configs by. The interval is the Wilson 95% interval of the recall.",
        "",
        "### At the configured thresholds",
        "",
    ]
    rows = []
    for name in shown:
        c = configs[name]
        for label, point in (("flag", c["flag"]), ("taint", c["taint"])):
            rows.append(
                [
                    NAMES[name],
                    f"{label} at {point['threshold']}",
                    num(point["precision"]),
                    num(point["recall"]),
                    num(point["f1"]),
                    num(point["fpr"], 3),
                ]
            )
    out += [
        table(["Config", "Threshold", "Precision", "Recall", "F1", "False positive rate"], rows),
        "",
    ]
    out += ["### False positives on hard negatives, on their own", ""]
    rows = []
    for name in shown:
        c = configs[name]
        hard = c["hard_negatives"]
        kinds = c["negatives_by_kind"]
        rows.append(
            [
                NAMES[name],
                rate(hard["flag"]),
                rate(hard["taint"]),
                rate(kinds["negative"]),
                rate(kinds["public"]),
            ]
        )
    out += [
        table(
            [
                "Config",
                f"Hard negatives flagged (at {flag})",
                f"Hard negatives tainting (at {taint})",
                "Harmless documents flagged",
                "Harmless public prompts flagged",
            ],
            rows,
        ),
        "",
        "The hard negatives are reported apart because a detector that flags how-to guides and "
        "business mail makes agents useless and gets switched off. By kind of text, at "
        f"{flag}:",
        "",
    ]
    families = sorted({f for name in shown for f in configs[name]["hard_negatives"]["by_family"]})
    rows = [
        [family, *(rate(configs[n]["hard_negatives"]["by_family"].get(family)) for n in shown)]
        for family in families
    ]
    out += [table(["Kind of hard negative", *(NAMES[n] for n in shown)], rows), ""]
    out += ["### Public prompts and documents apart", ""]
    rows = []
    for name in shown:
        for part in ("public", "documents"):
            sub = configs[name]["subsets"][part]
            rows.append(
                [
                    NAMES[name],
                    part,
                    f"{sub['n']} ({sub['injections']} injections)",
                    recall_cell(sub.get("recall_at_fpr_5pct")),
                    num(sub.get("roc_auc"), 3),
                ]
            )
    out += [
        table(
            ["Config", "Part", "Texts", "Recall at a false positive rate of 5% or less", "ROC AUC"],
            rows,
        ),
        "",
        "The attacks of the documents are the 12 templates that the rules were written against, "
        "so the rules' recall on them says less than it seems to. The public prompts are the "
        "independent check. They include German prompts and role-play requests, and the model's "
        "card says it handles neither non-English prompts nor jailbreaks.",
        "",
        "### Time of a scan",
        "",
        "One text at a time, in milliseconds, by length (four characters make a token). The model "
        "runs on the CPU of the machine above and is given as long as it needs.",
        "",
    ]
    rows = []
    for name in shown:
        latency = configs[name]["latency"]
        for bucket in ("under 500", "500 to 2000", "over 2000"):
            cell = latency[bucket]
            rows.append(
                [
                    NAMES[name],
                    bucket,
                    str(cell["n"]),
                    num(cell["p50_ms"], 1),
                    num(cell["p95_ms"], 1),
                ]
            )
    out += [table(["Config", "Tokens", "Texts", "p50 ms", "p95 ms"], rows), ""]
    if "combined_300ms" in configs:
        c = configs["combined_300ms"]
        out += [
            "### With the 300 ms wait of the gateway",
            "",
            "The gateway waits 300 ms for the model and then goes on with the rules. This row is "
            "computed from the measured time of each scan: a text whose scan took longer is "
            "scored by its rules alone.",
            "",
            table(
                [
                    "Config",
                    "Recall at a false positive rate of 5% or less",
                    "Hard negatives flagged",
                    "Scans that fell back",
                ],
                [
                    [
                        NAMES["combined_300ms"],
                        recall_cell(c["recall_at_fpr_5pct"]),
                        rate(c["hard_negatives"]["flag"]),
                        rate(c["fell_back_to_rules"]),
                    ]
                ],
            ),
            "",
        ]
    if "combined" in configs:
        out += ["### Recall by kind of attack (rules and model, flagged at " + str(flag) + ")", ""]
        c = configs["combined"]
        out += [
            table(
                ["Family", "Recall"],
                [[family, rate(cell)] for family, cell in c["recall_by_family"].items()],
            ),
            "",
            table(
                ["Hidden with", "Recall"],
                [[how, rate(cell)] for how, cell in c["recall_by_hidden"].items()],
            ),
            "",
        ]
    out += [
        "### What is and is not in these numbers",
        "",
        f"- The model is `{MODEL}` at revision `{MODEL_REVISION[:7]}`. Its card says it is for "
        "English and does not detect jailbreaks, which is most of the public prompts.",
        "- Thresholds were chosen on dev by `eval/detector/tune.py` (see `eval/results/`) and were "
        "not changed after the test split was scored.",
        "- A rate over 84 or fewer texts is wide. The intervals above say how wide.",
        "- Images are not read by the scanner, so there are none in the data.",
        "- The numbers are for one machine and one day. The times in particular move with the load "
        "of the machine (`docs/spikes/scanner.md` found five to seven times between a quiet "
        "machine and a busy one).",
    ]
    return "\n".join(out) + "\n"


def update_results(path: Path, section: str) -> None:
    """Put `section` between the markers of the document, or create the document."""
    block = f"{START}\n{section.rstrip()}\n{END}\n"
    if path.is_file() and START in path.read_text(encoding="utf-8"):
        text = path.read_text(encoding="utf-8")
        head, _, rest = text.partition(START)
        _, _, tail = rest.partition(END)
        path.write_text(head + block + tail.lstrip("\n"), encoding="utf-8")
        return
    intro = (
        "# Results\n\n"
        "What Keystone was measured to do, with the date and the commit of every measurement. "
        "A section is written by the tool that measured it, and a number that was not measured is "
        "not in this file.\n\n"
    )
    existing = path.read_text(encoding="utf-8") if path.is_file() else intro
    path.write_text(existing.rstrip("\n") + "\n\n" + block, encoding="utf-8")


def count_test_runs(path: Path | None = None) -> int:
    path = path or run.RUN_LOG
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def dataset_facts(data: Dataset) -> dict[str, Any]:
    manifest = load_manifest(MANIFEST) or {}
    return {
        "counts": dict(data.parts),
        "notes": list(data.notes),
        "sources": manifest.get("sources", {}),
        "manifest_version": manifest.get("version"),
        "seed": manifest.get("seed"),
    }


def build_document(
    data: Dataset, *, limit: int | None = None, settings: ScannerSettings | None = None
) -> dict[str, Any]:
    """Score the test split and gather every number and fact of the report."""
    base = settings or ScannerSettings()

    def progress(done: int, total: int) -> None:
        if done % 100 == 0 or done == total:
            print(f"  scored {done} of {total}", file=sys.stderr, flush=True)

    result = run_split(
        data,
        "test",
        ("rules", "classifier", "combined"),
        limit=limit,
        settings=base,
        progress=progress,
    )
    state = git_state()
    return {
        "date": datetime.now(UTC).date().isoformat(),
        **state,
        "machine": machine(),
        "model": {"id": MODEL, "revision": MODEL_REVISION, "classifier": base.classifier},
        "dataset": dataset_facts(data),
        "test_runs": count_test_runs(),
        "result": result,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the report of the detector evaluation")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="a sample of the test split: printed, no report written, but logged like any look",
    )
    parser.add_argument("--offline", action="store_true", help="do not download the public parts")
    parser.add_argument("--no-docs", action="store_true", help="do not touch docs/results.md")
    args = parser.parse_args(argv)

    data = build(download=not args.offline)
    document = build_document(data, limit=args.limit)
    # The test split was read, so the run is logged, a sample or not.
    log_test_run(document["result"], note=f"report with --limit {args.limit}" if args.limit else "")
    if args.limit:
        print(render_section(document))
        return 0
    RESULTS.mkdir(parents=True, exist_ok=True)
    target = RESULTS / f"detector-{document['date']}.json"
    target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not args.no_docs:
        update_results(RESULTS_DOC, render_section(document))
    print(f"wrote {target.relative_to(REPO) if target.is_relative_to(REPO) else target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
