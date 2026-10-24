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

It scores the test split once with the rules and the model, in three passes of the scanner over the
same texts, and computes the metrics of the configs they give:

- `rules`, and `combined` with its 300 ms row: the scanner as it is set now (KS-792), which joins
  the rules and the model rules first and reads in windows of 128 tokens;
- `classifier`: the model alone, at the same windows, which needs a scanner that asks it about every
  text (`join: max`);
- `previous_classifier`, `previous_combined` and its 300 ms row: the scanner as Phase 7 shipped it,
  the higher of the two scores over windows of 510 tokens, so that the change is measured and not
  told.

It writes two things: the file `eval/results/detector-<date>.json` with every number, and the
detector section of `docs/results.md` with the ones a reader needs. Both say the date, the commit
the code was at and whether the tree was clean, the revision of every public dataset, the
thresholds and the machine, because a number without those is not a result. The section also
tells how the join was picked on the dev split, from the record that `eval.detector.combine` left
in `eval/results/combination-dev-<date>.json`.

Nothing here invents a figure. A cell is filled from the JSON, and where the JSON has none (a bucket
with no text in it, a config that was not run) the cell says "not measured".
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
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
# The order of the rows of a table, and the configs that make a row of their own.
ORDER = ("rules", "previous_classifier", "previous_combined", "classifier", "combined")
# What Phase 7 shipped: the higher of the two scores over windows of 512 tokens (510 of the text).
PREVIOUS = ScannerSettings(join="max", window_tokens=510, window_overlap=64)
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
    """The configs of a logged run in words. A 300 ms row is derived and is not a config."""
    base = sorted(c for c in configs if not c.endswith("combined_300ms"))
    if base == ["rules"]:
        return "rules only"
    if base == ["classifier", "combined", "rules"]:
        return "all three configs"
    if "previous_combined" in base:
        return "the scanner as it is set now and as Phase 7 shipped it"
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


def names_of(result: Mapping[str, Any]) -> dict[str, str]:
    """What each config is called in a table, with the windows it reads in, from the run's own
    record of its settings."""
    now = result.get("scanner") or {}
    before = result.get("previous_scanner") or {}
    windows = f"windows of {now['window_tokens']}" if now else "windows"
    earlier = f"windows of {before['window_tokens']}" if before else "windows"
    return {
        "rules": "Rules",
        "previous_classifier": f"Model, {earlier} (Phase 7)",
        "previous_combined": f"Higher of the two, {earlier} (Phase 7)",
        "previous_combined_300ms": f"Higher of the two, {earlier}, 300 ms wait",
        "classifier": f"Model, {windows}",
        "combined": "Rules first, then the model",
        "combined_300ms": "Rules first, then the model, 300 ms wait",
    }


def recall_of(configs: Mapping[str, Any], name: str) -> float | None:
    point = (configs.get(name) or {}).get("recall_at_fpr_5pct")
    return None if not point else float(point["recall"])


def reading(
    configs: Mapping[str, Any], shown: Sequence[str], names: Mapping[str, str]
) -> list[str]:
    """What the first table shows, said once and from the numbers: which row finds most at a false
    positive rate of 5% or less, and how the rows compare with the rules alone."""
    ranked = [n for n in shown if recall_of(configs, n) is not None]
    if len(ranked) < 2:
        return []
    top = max(ranked, key=lambda n: recall_of(configs, n) or 0.0)
    rules = recall_of(configs, "rules")
    sentence = (
        f"At a false positive rate of 5% or less the row that finds most is {names[top]} "
        f"({recall_of(configs, top):.2f})."
    )
    if rules is not None and top != "rules":
        sentence += f" The rules alone find {rules:.2f}."
    older = recall_of(configs, "previous_combined")
    now = recall_of(configs, "combined")
    if older is not None and now is not None and rules is not None:
        if older < rules:
            sentence += (
                f" The higher of the two scores found less than the rules alone ({older:.2f} "
                f"against {rules:.2f}), because it keeps every false positive of the model."
            )
        if now < rules:
            sentence += (
                f" Rules first, then the model, finds less than the rules alone ({now:.2f} "
                f"against {rules:.2f}) on this split."
            )
    return [sentence, ""]


def waiting_caution(configs: Mapping[str, Any]) -> list[str]:
    """Why the rows for the 300 ms wait are weak numbers, from the thresholds of the rows above."""
    point = (configs.get("combined") or {}).get("recall_at_fpr_5pct") or {}
    threshold = point.get("threshold")
    where = "near the top of its range" if threshold is None else f"at {threshold:.2f}"
    return [
        "Recall at a false positive rate of 5% depends on the few harmless texts that score "
        f"highest. The threshold of the rules first row sits {where}, set by the harmless texts "
        "that score high, so a row for the wait changes with which of those texts happen to be "
        "among the scans that fell back to the rules. Read it as what the wait does to this "
        "sample and not as a property of the detector.",
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


def percent(value: float | None) -> str:
    return NOT if value is None else f"{100 * value:.0f}%"


def combination_sections(record: Mapping[str, Any] | None) -> list[str]:
    """How the join and the windows were picked on dev, from the record the sweep left."""
    if not record:
        return []
    chosen = record["chosen"]
    shape = chosen["shape"]
    size, _, overlap = shape.partition("/")
    weight = chosen["combiner"]["params"]["weight"]
    rows = record["rows"]
    shapes = sorted({r["shape"] for r in rows}, key=lambda key: -int(key.split("/")[0]))

    def find(key: str, name: str, **params: float) -> Mapping[str, Any] | None:
        for r in rows:
            if (
                r["shape"] == key
                and r["aggregate"] == "max"
                and r["combiner"]["name"] == name
                and all(r["combiner"]["params"].get(k) == v for k, v in params.items())
            ):
                return r
        return None

    def recall(r: Mapping[str, Any] | None) -> str:
        return NOT if r is None else f"{r['recall_at_fpr_5pct']:.2f}"

    rules_row = find(shapes[0], "rules")
    out = [
        "### How the join and the windows were picked, on the dev split",
        "",
        f"Dev has {record['n']} texts and {record['injections']} injections. "
        f"`python -m eval.detector.combine` tried {record['candidates']} candidates on it (a "
        "shape of window, how the windows of a text are made one score, and a way to join that "
        "with the rules' score) and the test split was not read. Recall at a false positive "
        "rate of 5% or less on dev, by the windows the model reads in "
        f"(the rules alone find {recall(rules_row)}, whatever the windows):",
        "",
        table(
            [
                "Windows of",
                "Model alone",
                "Higher of the two",
                f"Rules first, then the model (weight {weight})",
            ],
            [
                [
                    key.split("/")[0],
                    recall(find(key, "model")),
                    recall(find(key, "max")),
                    recall(find(key, "rules_first", floor=0.5, weight=weight)),
                ]
                for key in shapes
            ],
        ),
        "",
    ]
    diagnosis = record.get("diagnosis") or {}
    if diagnosis:
        header = [
            "Kind of text",
            "Texts",
            "Rules",
            *(f"Model, windows of {k.split('/')[0]}" for k in shapes),
        ]
        body = []
        for kind, info in diagnosis.items():
            body.append(
                [
                    kind,
                    str(info["n"]),
                    percent(info["rules_at_0.5"]),
                    *(percent(info["model"][k]["at_0.5"]) for k in shapes),
                ]
            )
        out += [
            "Why the model was weak on documents: the share of each kind of text that scores "
            "0.5 or more, from the model alone and from the rules. A long window holds an attack "
            "and the document around it, and the model scores the whole.",
            "",
            table(header, body),
            "",
        ]
    boot = record.get("bootstrap") or {}
    gain = (boot.get("gain_over_reference") or {}).get("chosen")
    older = (boot.get("gain_over_reference") or {}).get("phase 7")
    if gain:
        out += [
            f"Resampling the carriers of dev {boot['resamples']} times, rules first with windows "
            f"of {size} finds {gain['mean']:+.2f} (95% {gain['low']:+.2f} to "
            f"{gain['high']:+.2f}) of the injections more than the rules alone at a false positive "
            "rate of 5%"
            + (
                f", and the higher of the two over windows of 510 finds {older['mean']:+.2f} "
                f"(95% {older['low']:+.2f} to {older['high']:+.2f})."
                if older
                else "."
            ),
            "",
        ]
    out += [
        f"I picked windows of {size} tokens with an overlap of {overlap} and a model weight of "
        f"{weight} by a rule written before the numbers: of the joins the "
        "gateway can run, the candidates within the noise of the best recall on dev (7 of the "
        f"{record['injections']} injections) are tied, and of those the larger window wins. "
        "The test split was scored once, with that choice.",
        "",
    ]
    return out


def skipped_note(result: Mapping[str, Any]) -> list[str]:
    """Why the scans of rules first, then the model, are shorter: it does not ask the model about a
    text the rules flag."""
    skipped, total = result.get("model_skipped"), result["samples"]["n"]
    if not skipped:
        return []
    return [
        "Rules first, then the model, does not give the model a text that the rules flag "
        f"({skipped} of the {total} texts of this run), so its scans are shorter than those of "
        "the model alone. A scan with the model runs the rules too.",
        "",
    ]


def kinds_of_attack(configs: Mapping[str, Any], names: Mapping[str, str]) -> list[str]:
    """Recall by family, by how the attack was hidden and by template, for the rules, for what
    Phase 7 shipped and for the scanner as it is set now."""
    columns = [n for n in ("rules", "previous_combined", "combined") if n in configs]
    out: list[str] = []
    for title, key in (
        ("Family", "recall_by_family"),
        ("Hidden with", "recall_by_hidden"),
        ("Template", "recall_by_template"),
    ):
        kinds = sorted({k for n in columns for k in configs[n][key]})
        rows = [[k, *(rate(configs[n][key].get(k)) for n in columns)] for k in kinds]
        out += [table([title, *(names[n] for n in columns)], rows), ""]
    return out


def limits(document: Mapping[str, Any], shown: Sequence[str]) -> list[str]:
    """What the numbers do not say."""
    result = document["result"]
    configs = configs_of(document)
    now = result.get("scanner") or {}
    record = document.get("combination") or {}
    out = [
        f"- The model is `{MODEL}` at revision `{MODEL_REVISION[:7]}`. Its card says it is for "
        "English and does not detect jailbreaks."
        + (
            f" It reads in windows of {now['window_tokens']} tokens that overlap by "
            f"{now['window_overlap']}."
            if now
            else ""
        )
    ]
    if now.get("join") == "rules_first":
        out.append(
            "- Rules first, then the model, lets the model add to a score that the rules left "
            f"under the flag threshold, at a weight of {now['model_weight']}. So the model alone "
            "can flag a text and cannot make an injection of it: only the rules can taint a "
            "session (ADR-0011)."
        )
    if record:
        out.append(
            f"- The windows and the weight were picked on dev from {record['candidates']} "
            "candidates, so the recall of the chosen one on dev is higher than a sample it was not "
            "picked on would give. The test split is that sample, and it was scored once with the "
            "choice."
        )
    out += [
        *small_groups(configs, shown),
        "- Prompt Guard 2 (`prompt-guard-2-86m`) was not measured: its files answer 401 without a "
        "Hugging Face login and the acceptance of the Llama license, and ADR-0011 records the "
        "check.",
        "- Images are not read by the scanner, so there are none in the data.",
        "- The numbers are for one machine and one day. The times in particular move with the load "
        "of the machine (`docs/spikes/scanner.md` found five to seven times between a quiet "
        "machine and a busy one).",
    ]
    return out


def render_section(document: Mapping[str, Any]) -> str:
    """The detector section of docs/results.md, from a report document."""
    result = document["result"]
    configs = configs_of(document)
    names = names_of(result)
    shown = [name for name in ORDER if name in configs]
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
    out += ["", *combination_sections(document.get("combination"))]
    out += ["### How good the scores are", ""]
    rows = []
    for name in shown:
        c = configs[name]
        rows.append(
            [
                names[name],
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
        *reading(configs, shown, names),
        "### At the configured thresholds",
        "",
    ]
    rows = []
    for name in shown:
        c = configs[name]
        for label, point in (("flag", c["flag"]), ("taint", c["taint"])):
            rows.append(
                [
                    names[name],
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
                names[name],
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
    out += [table(["Kind of hard negative", *(names[n] for n in shown)], rows), ""]
    out += ["### Public prompts and documents apart", ""]
    rows = []
    for name in shown:
        for part in ("public", "documents"):
            sub = configs[name]["subsets"][part]
            rows.append(
                [
                    names[name],
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
                    names[name],
                    bucket,
                    str(cell["n"]),
                    num(cell["p50_ms"], 1),
                    num(cell["p95_ms"], 1),
                ]
            )
    out += [
        table(["Config", "Tokens", "Texts", "p50 ms", "p95 ms"], rows),
        "",
        *skipped_note(result),
    ]
    waiting = [n for n in ("previous_combined_300ms", "combined_300ms") if n in configs]
    if waiting:
        out += [
            "### With the 300 ms wait of the gateway",
            "",
            "The gateway waits 300 ms for the model and then goes on with the rules. These rows "
            "are computed from the measured time of each scan: a text whose scan took longer is "
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
                        names[name],
                        recall_cell(configs[name]["recall_at_fpr_5pct"]),
                        rate(configs[name]["hard_negatives"]["flag"]),
                        rate(configs[name]["fell_back_to_rules"]),
                    ]
                    for name in waiting
                ],
            ),
            "",
            *waiting_caution(configs),
        ]
    if "combined" in configs:
        out += [f"### Recall by kind of attack (flagged at {flag})", ""]
        out += kinds_of_attack(configs, names)
    out += [
        "### What is and is not in these numbers",
        "",
        *limits(document, shown),
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


def run_passes(
    data: Dataset,
    split: str,
    base: ScannerSettings,
    *,
    limit: int | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Score a split in three passes of the scanner over the same texts and merge the configs
    (see the top of this file): the scanner as set in `base`, the model alone at the same windows,
    and the scanner as Phase 7 shipped it."""
    current = run_split(
        data, split, ("rules", "combined"), limit=limit, settings=base, progress=progress
    )
    alone = run_split(
        data,
        split,
        ("classifier",),
        limit=limit,
        settings=base.model_copy(update={"join": "max"}),
        progress=progress,
    )
    earlier = base.model_copy(
        update=PREVIOUS.model_dump(include={"join", "window_tokens", "window_overlap"})
    )
    before = run_split(
        data, split, ("classifier", "combined"), limit=limit, settings=earlier, progress=progress
    )
    result = dict(current)
    result["configs"] = {
        **current["configs"],
        "classifier": alone["configs"]["classifier"],
        **{f"previous_{name}": cell for name, cell in before["configs"].items() if name != "rules"},
    }
    result["previous_scanner"] = before["scanner"]
    result["model_failures"] = (
        current["model_failures"] + alone["model_failures"] + before["model_failures"]
    )
    return result


def combination_record() -> dict[str, Any] | None:
    """The latest record that `eval.detector.combine` left of the sweep on dev, or None."""
    found = sorted(RESULTS.glob("combination-dev-*.json"))
    if not found:
        return None
    record: dict[str, Any] = json.loads(found[-1].read_text(encoding="utf-8"))
    record["file"] = found[-1].name
    return record


def build_document(
    data: Dataset, *, limit: int | None = None, settings: ScannerSettings | None = None
) -> dict[str, Any]:
    """Score the test split and gather every number and fact of the report."""
    base = settings or ScannerSettings()

    def progress(done: int, total: int) -> None:
        if done % 100 == 0 or done == total:
            print(f"  scored {done} of {total}", file=sys.stderr, flush=True)

    result = run_passes(data, "test", base, limit=limit, progress=progress)
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
        "combination": combination_record(),
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
