"""Write the report of the detector evaluation (KS-707).

    python -m eval.detector.report                # all three configs on the test split
    python -m eval.detector.report --limit 200    # a sample: printed, no report written
    python -m eval.detector.report --note "why"   # the reason goes into the log line of the run
    python -m eval.detector.report --render eval/results/detector-<date>.json
                                                  # docs/results.md again from a saved report

`--render` scores nothing and logs nothing: it writes the same numbers in the words that the code
has now, so a change to the text of the report does not need another look at the test split.

Every run reads the test split, a sample too, and so every run is logged in
`eval/results/test-runs.jsonl` (`run.log_test_run`). The report says how many runs there were
before it, and what they were.

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
from collections import Counter
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


def short(path: Path) -> Path:
    """A path relative to the repository when it is in it, for a line of output."""
    return path.relative_to(REPO) if path.is_relative_to(REPO) else path


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def tuning_sentence(tuning: Mapping[str, Any] | None, flag: float, taint: float) -> str:
    """What the dev sweep said about the thresholds used here, from the record it left."""
    used = (
        f"The thresholds are the configured ones: a text is flagged at {flag} and a session is "
        f"tainted at {taint}."
    )
    if not tuning:
        return f"{used} No tuning record is kept in `eval/results/`."
    chosen, floor = tuning["recommended"], tuning["precision_floor"]
    best, wanted = chosen["suspicious"], chosen["injection"]
    first = f"the best F0.5 of the combined score was at {best}"
    if best != flag:
        first += f", not {flag}"
    if wanted is None:
        second = f"no threshold reached a precision of {floor} for tainting"
    elif wanted == taint:
        second = f"{taint} was the lowest threshold with a precision of {floor} for tainting"
    else:
        second = (
            f"the lowest threshold with a precision of {floor} for tainting was {wanted}, "
            f"not {taint}"
        )
    stayed = best == flag and wanted in (None, taint)
    kept = "so they stayed." if stayed else "and this report uses the configured ones."
    return (
        f"{used} They were checked on the dev split only ({tuning['n']} texts, "
        f"`eval/results/{tuning['file']}`): {first}, and {second}, {kept}"
    )


def describe_configs(configs: Sequence[str]) -> str:
    """The configs of a logged run in words. The 300 ms row is derived and is not a config."""
    base = sorted(c for c in configs if c != "combined_300ms")
    if base == ["rules"]:
        return "rules only"
    if base == ["classifier", "combined", "rules"]:
        return "all three configs"
    return ", ".join(base)


def scored_before(document: Mapping[str, Any]) -> str:
    """How many times the test split was scored before this report, and what those runs were."""
    earlier = document.get("earlier_runs", [])
    head = (
        f"The test split was scored {plural(document['test_runs'], 'time')} before this report; "
        f"every run is in `eval/results/test-runs.jsonl`{':' if earlier else '.'}"
    )
    lines = []
    for entry in earlier:
        tree = " with uncommitted changes" if entry.get("dirty") else ""
        where = f"{entry['at'][:10]}, commit `{entry['commit'][:12]}`{tree}"
        what = f"{plural(entry['n'], 'text')}, {describe_configs(entry['configs'])}"
        lines.append(f"- {where}, {what}" + (f": {entry['note']}." if entry.get("note") else "."))
    return "\n".join([head, "", *lines]) if lines else head


def reading(configs: Mapping[str, Any], shown: Sequence[str], flag: float) -> list[str]:
    """What the first table shows when its rows pull apart, said once and from the numbers."""
    ranked = [n for n in shown if configs[n]["roc_auc"] is not None]
    if len(ranked) < 2:
        return []
    top = max(ranked, key=lambda n: configs[n]["roc_auc"])
    sentence = f"The best ROC AUC is that of {NAMES[top]} ({configs[top]['roc_auc']:.3f})."
    if top != "rules" and {"rules", "classifier", "combined"} <= configs.keys():
        at_rules = (configs["rules"]["recall_at_fpr_5pct"] or {}).get("recall")
        at_both = (configs["combined"]["recall_at_fpr_5pct"] or {}).get("recall")
        documents = configs["classifier"]["negatives_by_kind"]["negative"]
        hard = configs["classifier"]["hard_negatives"]["flag"]
        if at_rules is not None and at_both is not None and at_both < at_rules:
            sentence = (
                f"The best ROC AUC is that of {NAMES[top]} ({configs[top]['roc_auc']:.3f}), but "
                f"at a false positive rate of 5% or less the rules alone find more attacks "
                f"({at_rules:.2f} against {at_both:.2f}). The combined score is the higher of the "
                "two scores, so every harmless text that the model flags is flagged by it too: "
                f"at {flag} the model flags {documents['count']} of {documents['of']} harmless "
                f"documents and {hard['count']} of {hard['of']} hard negatives."
            )
    return [sentence, ""]


def waiting_caution(configs: Mapping[str, Any]) -> list[str]:
    """Why the row for the 300 ms wait is a weak number, from the threshold of the rows above."""
    point = (configs.get("combined") or {}).get("recall_at_fpr_5pct") or {}
    threshold = point.get("threshold")
    where = "near the top of its range" if threshold is None else f"at {threshold:.2f}"
    return [
        "Recall at a false positive rate of 5% depends on the few harmless texts that score "
        f"highest. The threshold of the rules and model row sits {where}, set by the harmless "
        "texts that the model gives a high score, so this row changes with which of those texts "
        "happen to be among the scans that fell back to the rules. Read it as what the wait does "
        "to this sample and not as a property of the detector.",
        "",
    ]


def small_groups(configs: Mapping[str, Any], shown: Sequence[str]) -> list[str]:
    """A line about how few texts some rates rest on, from the sizes of the groups."""
    if not shown:
        return []
    hard = configs[shown[0]]["hard_negatives"]
    sizes = [cell["of"] for cell in hard["by_family"].values()]
    if not sizes:
        return []
    return [
        f"- The test split has {hard['flag']['of']} hard negatives, and each kind of them is "
        f"{min(sizes)} to {max(sizes)} texts. A rate over so few texts is wide, and the "
        "intervals above say how wide."
    ]


def render_section(document: Mapping[str, Any]) -> str:
    """The detector section of docs/results.md, from a report document."""
    result = document["result"]
    configs = configs_of(document)
    shown = [name for name in ("rules", "classifier", "combined") if name in configs]
    flag, taint = result["thresholds"]["flag"], result["thresholds"]["taint"]
    samples = result["samples"]
    commit = document["commit"][:12] + (" plus uncommitted changes" if document["dirty"] else "")
    sources = document["dataset"]["sources"]
    counts = document["dataset"]["counts"]
    kinds = document["dataset"].get("kinds", {})
    hard_total = kinds.get("hard_negative", 0)
    generated = counts.get("synthetic", 0) - hard_total
    tuned = tuning_sentence(document.get("tuning"), flag, taint)
    out = [
        "## Detector",
        "",
        f"Measured on {document['date']} at commit `{commit}`, on "
        f"{document['machine']['platform']} ({document['machine']['cpus']} CPUs, "
        f"Python {document['machine']['python']}), by `python -m eval.detector.report`. Every "
        f"number below is in `eval/results/detector-{document['date']}.json`.",
        "",
        f"The test split has {samples['n']} texts from {samples['carriers']} carriers, "
        f"{samples['injections']} of them injections. {tuned}",
        "",
        scored_before(document),
        "",
        "The data (`eval/DATASETS.md` has sources and licenses). The counts are those of the whole "
        "dataset, which dev and test share between them:",
        "",
        "- **Public prompts**: "
        f"`{sources['public']['dataset']}`, {counts.get('public', 0)} prompts of both labels, in "
        "English and German. They are direct requests to a model and not documents.",
        "- **Documents**: emails, pages and files, harmless as they are and with one of 12 attacks "
        "from `examples/fixtures/injections/templates.yaml` put at the start, middle or end, a "
        f"quarter of them hidden with invisible characters. {generated} texts are generated from "
        f"the fixtures of this repository, and {counts.get('wikitext', 0)} are built on articles "
        f"of `{sources['wikitext']['dataset']}`.",
        f"- **Hard negatives**: {hard_total} harmless texts that sound like instructions (how-to "
        "guides, recipes, business mail, and security articles that quote attacks).",
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
        *reading(configs, shown, flag),
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
        "The attacks of the documents are the 12 templates of this repository, which were "
        "written alongside the rules, so the rules' recall on them says less than it seems to. "
        "The public prompts are the independent check. They include prompts in German, and the "
        "model's card says it is for English.",
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
    out += [
        table(["Config", "Tokens", "Texts", "p50 ms", "p95 ms"], rows),
        "",
        "A scan with the model runs the rules too, so the last two rows are the same scans.",
        "",
    ]
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
            *waiting_caution(configs),
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
        "English and does not detect jailbreaks.",
        *small_groups(configs, shown),
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


def tuning_record() -> dict[str, Any] | None:
    """The latest record that `tune.py` left for the combined score, or None."""
    found = sorted(RESULTS.glob("tuning-*-combined.json"))
    if not found:
        return None
    record = json.loads(found[-1].read_text(encoding="utf-8"))
    return {
        "file": found[-1].name,
        "date": record["date"],
        "n": record["n"],
        "recommended": record["recommended"],
        "precision_floor": record["recommended"]["precision_floor"],
        "current": record["current"],
    }


def earlier_runs(path: Path | None = None) -> list[dict[str, Any]]:
    """The lines of the log of runs on the test split."""
    path = path or run.RUN_LOG
    if not path.is_file():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def dataset_facts(data: Dataset) -> dict[str, Any]:
    manifest = load_manifest(MANIFEST) or {}
    return {
        "counts": dict(data.parts),
        "kinds": dict(Counter(s.kind for s in data.samples)),
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
        "earlier_runs": earlier_runs(),
        "tuning": tuning_record(),
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
    parser.add_argument("--note", default="", help="why this run was made, for its line of the log")
    parser.add_argument(
        "--render",
        type=Path,
        default=None,
        help="write docs/results.md from this saved report; nothing is scored or logged",
    )
    args = parser.parse_args(argv)

    if args.render:
        saved = json.loads(args.render.read_text(encoding="utf-8"))
        update_results(RESULTS_DOC, render_section(saved))
        print(f"wrote {short(RESULTS_DOC)}")
        return 0
    data = build(download=not args.offline)
    document = build_document(data, limit=args.limit)
    # The test split was read, so the run is logged, a sample or not.
    why = [f"report with --limit {args.limit}" if args.limit else "", args.note]
    log_test_run(document["result"], note="; ".join(w for w in why if w))
    if args.limit:
        print(render_section(document))
        return 0
    RESULTS.mkdir(parents=True, exist_ok=True)
    target = RESULTS / f"detector-{document['date']}.json"
    target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not args.no_docs:
        update_results(RESULTS_DOC, render_section(document))
    print(f"wrote {short(target)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
