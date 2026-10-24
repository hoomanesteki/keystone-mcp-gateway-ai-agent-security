"""Write the performance section of docs/results.md from a matrix result (KS-903).

    python -m eval.perf.report                    # the newest eval/results/perf-*.json
    python -m eval.perf.report --check            # fail when docs/results.md is not what it renders
    python -m eval.perf.report FILE               # this file

It reads `eval/results/perf-<date>.json`, which `python -m eval.perf.matrix` wrote, and nothing
else. Every figure is computed here from the latencies in that file (the percentiles by the same
nearest-rank rule as the detector's latency table) and from the counters the gateway kept, and the
section names the file, the commit and the machine. A target that was not run, or a stage that was
not counted, is left out and not filled in.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from eval.perf.stats import PERCENTILES, overhead, summarize
from eval.redteam.suite import REPO
from keystone.gateway.wiring import INTERCEPTOR_ORDER

RESULTS = REPO / "eval" / "results"
RESULTS_DOC = REPO / "docs" / "results.md"
START = "<!-- perf:start -->"
END = "<!-- perf:end -->"
NOT = "not measured"
# The targets of M5 and M6 (docs/PLAN.md section 1): the added latency per tool call at 200
# concurrent sessions, with the scanner off, and with the classifier for outputs of up to 2,000
# tokens.
M5_P50_MS = 10.0
M5_P95_MS = 25.0
M6_P95_MS = 150.0
M6_TOKENS = 2000
BYTES_PER_TOKEN = 4  # the guess used when the file does not say how many tokens a payload is
ORDER = ("direct", "passthrough", "scanner-off", "rules-only", "classifier")


def load(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return document


def find_files(folder: Path = RESULTS) -> list[Path]:
    return sorted(folder.glob("perf-*.json"))


# -- the numbers


def summary_of(run: Mapping[str, Any]) -> dict[str, Any]:
    """The summary of a run, computed again from its latencies, so that the section does not trust
    the summary the matrix wrote. The wall time and the failed calls are the matrix's."""
    wall = run["summary"]["wall_s"]
    return summarize(run["latencies_ms"], wall, run["summary"]["errors"])


def runs_of(document: Mapping[str, Any], key: str, sequential: bool = False) -> dict[int, Any]:
    entry = document["targets"].get(key)
    if not entry:
        return {}
    return {run["size"]: run for run in entry["sequential" if sequential else "runs"]}


def tokens_of(document: Mapping[str, Any], size: int) -> int:
    counted = document["settings"].get("payload_tokens", {}).get(str(size))
    return int(counted) if counted else size // BYTES_PER_TOKEN


def added(document: Mapping[str, Any], key: str, size: int, sequential: bool = False) -> Any:
    """What a target adds to the upstream alone at each percentile, or None if either is missing."""
    mine = runs_of(document, key, sequential).get(size)
    base = runs_of(document, "direct", sequential).get(size)
    if not mine or not base or not mine["summary"] or not base["summary"]:
        return None
    return overhead(summary_of(mine), summary_of(base))


def generator_busy(run: Mapping[str, Any]) -> float:
    """The busiest process of the generator, as a share of one CPU, over the timed calls."""
    return max((p["cpu_s"] / p["wall_s"] for p in run["generator"] if p["wall_s"] > 0), default=0.0)


# -- words


def ms(value: float | None) -> str:
    return NOT if value is None else f"{value:.1f}"


def signed(value: float | None) -> str:
    return NOT if value is None else f"{value:+.1f}"


def table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    return "\n".join(
        [
            "| " + " | ".join(header) + " |",
            "|" + "|".join("---" for _ in header) + "|",
            *("| " + " | ".join(row) + " |" for row in rows),
        ]
    )


def kb(size: int) -> str:
    return f"{size // 1024} KB" if size % 1024 == 0 else f"{size} bytes"


def gib(value: int | None) -> str:
    return NOT if not value else f"{value / 2**30:.0f} GB"


def latency_table(document: Mapping[str, Any], size: int, sequential: bool) -> str:
    header = [
        "Target",
        "p50 (ms)",
        "p95 (ms)",
        "p99 (ms)",
        "Added p50",
        "Added p95",
        "Added p99",
        "Calls / s",
        "Errors",
    ]
    rows = []
    for key in ORDER:
        run = runs_of(document, key, sequential).get(size)
        if not run or not run["summary"]:
            continue
        s = summary_of(run)
        extra = None if key == "direct" else added(document, key, size, sequential)
        rows.append(
            [
                document["targets"][key]["label"],
                ms(s["p50_ms"]),
                ms(s["p95_ms"]),
                ms(s["p99_ms"]),
                *(["-"] * 3 if extra is None else [signed(extra[f"p{q}_ms"]) for q in PERCENTILES]),
                f"{s['throughput']:.0f}",
                f"{s['errors']} of {s['calls']}",
            ]
        )
    return table(header, rows)


def stage_table(document: Mapping[str, Any], sequential: bool = False) -> list[str]:
    """The mean time a call spent in each stage of the gateway, for each Keystone target and
    payload, from the counters the gateway kept during the timed calls."""
    stages = ["total", "upstream", *INTERCEPTOR_ORDER]
    header = ["Target", "Payload", "Client mean (ms)", *[s.replace("_", " ") for s in stages]]
    rows = []
    for key in ORDER:
        if key == "direct":
            continue
        for size, run in runs_of(document, key, sequential).items():
            if not run.get("stages"):
                continue
            mean = summary_of(run)["mean_ms"]
            cells = [ms(run["stages"][s]["mean_ms"]) if s in run["stages"] else "-" for s in stages]
            rows.append([document["targets"][key]["label"], kb(size), ms(mean), *cells])
    return [table(header, rows)] if rows else []


def conditions_table(document: Mapping[str, Any]) -> str:
    header = [
        "Target",
        "Payload",
        "Host idle before",
        "Container CPU, mean (of 400%)",
        "Container CPU, highest",
        "Container memory, highest (MiB)",
        "Generator, busiest process",
    ]
    rows = []
    for key in ORDER:
        entry = document["targets"].get(key)
        if not entry:
            continue
        idle = (entry.get("conditions") or {}).get("idle_percent")
        for size, run in runs_of(document, key).items():
            box = run.get("container") or {}
            rows.append(
                [
                    entry["label"],
                    kb(size),
                    f"{idle:.0f}%" if idle is not None else NOT,
                    f"{box['cpu_percent_mean']:.0f}%" if box.get("samples") else "-",
                    f"{box['cpu_percent_max']:.0f}%" if box.get("samples") else "-",
                    f"{box['memory_mib_max']:.0f}" if box.get("samples") else "-",
                    f"{generator_busy(run) * 100:.0f}% of a CPU",
                ]
            )
    return table(header, rows)


def verdicts(document: Mapping[str, Any]) -> list[str]:
    """M5 and M6 against their targets, with the values this run measured."""
    rows: list[list[str]] = []
    sizes = document["settings"]["sizes"]
    sessions = document["settings"]["sessions"]

    shown, passed = [], []
    for size in sizes:
        extra = added(document, "scanner-off", size)
        if extra is None:
            continue
        shown.append(
            f"{kb(size)}: p50 {signed(extra['p50_ms'])} ms, p95 {signed(extra['p95_ms'])} ms"
        )
        passed.append(extra["p50_ms"] <= M5_P50_MS and extra["p95_ms"] <= M5_P95_MS)
    rows.append(
        [
            "M5",
            f"Added latency per call, scanner off, {sessions} sessions",
            f"p50 at most {M5_P50_MS:.0f} ms, p95 at most {M5_P95_MS:.0f} ms",
            "; ".join(shown) or NOT,
            ("met" if all(passed) else "not met") if passed else "",
        ]
    )
    shown, passed = [], []
    for size in sizes:
        if tokens_of(document, size) > M6_TOKENS:
            continue
        extra = added(document, "classifier", size)
        if extra is None:
            continue
        shown.append(
            f"{kb(size)} ({tokens_of(document, size)} tokens): p95 {signed(extra['p95_ms'])} ms"
        )
        passed.append(extra["p95_ms"] <= M6_P95_MS)
    rows.append(
        [
            "M6",
            f"Added latency per call, classifier, outputs up to {M6_TOKENS:,} tokens, "
            f"{sessions} sessions",
            f"p95 at most {M6_P95_MS:.0f} ms",
            "; ".join(shown) or NOT,
            ("met" if all(passed) else "not met") if passed else "",
        ]
    )
    return [table(["Metric", "What", "Target", "Measured", "Verdict"], rows)]


def reading(document: Mapping[str, Any]) -> list[str]:
    """What the numbers say, each sentence made from them."""
    out: list[str] = []
    sizes = document["settings"]["sizes"]
    sessions = document["settings"]["sessions"]
    first = sizes[0]
    off = runs_of(document, "scanner-off").get(first)
    direct = runs_of(document, "direct").get(first)
    if off and direct and off["summary"] and direct["summary"]:
        mine, base = summary_of(off), summary_of(direct)
        out.append(
            f"At {sessions} sessions the echo upstream alone answers at a median of "
            f"{base['p50_ms']:.1f} ms ({base['throughput']:.0f} calls a second), and Keystone with "
            f"the scanner off at {mine['p50_ms']:.1f} ms ({mine['throughput']:.0f} calls a second)."
        )
        stages = off.get("stages") or {}
        if "total" in stages:
            total = stages["total"]["mean_ms"]
            upstream = stages.get("upstream", {}).get("mean_ms", 0.0)
            inside = {s: stages[s]["mean_ms"] for s in INTERCEPTOR_ORDER if s in stages}
            biggest = max(inside, key=lambda name: inside[name], default=None)
            out.append(
                f"A call spent {total:.1f} ms on average inside the gateway, {upstream:.1f} ms of "
                f"it waiting for the upstream and {sum(inside.values()):.1f} ms in the nine slots"
                + (
                    f", the largest of them `{biggest}` at {inside[biggest]:.1f} ms"
                    if biggest
                    else ""
                )
                + f". The client saw a mean of {mine['mean_ms']:.1f} ms. The other "
                f"{max(mine['mean_ms'] - total, 0):.1f} ms is outside what the gateway counts: the "
                "request and the answer on the wire, the check of the token, the wait for the "
                "event loop before the pipeline starts, and the generator's own time."
            )
    seq_extra = added(document, "scanner-off", first, sequential=True)
    off_extra = added(document, "scanner-off", first)
    if seq_extra and off_extra:
        out.append(
            "With one session and no queue the scanner-off gateway adds p50 "
            f"{seq_extra['p50_ms']:.1f} ms and p95 {seq_extra['p95_ms']:.1f} ms at {kb(first)}; "
            f"with {sessions} sessions it adds p50 {off_extra['p50_ms']:.1f} ms and p95 "
            f"{off_extra['p95_ms']:.1f} ms."
        )
    cls = runs_of(document, "classifier").get(first)
    if cls and cls.get("stages") and "output_scan" in cls["stages"]:
        scan = cls["stages"]["output_scan"]["mean_ms"]
        rules = runs_of(document, "rules-only").get(first)
        rules_scan = (rules or {}).get("stages", {}).get("output_scan", {}).get("mean_ms")
        out.append(
            f"The scan took {scan:.1f} ms on average with the classifier"
            + (f" and {rules_scan:.1f} ms with the rules alone" if rules_scan is not None else "")
            + f" at {kb(first)}."
        )
    stopped = [
        f"{document['targets'][key]['label']} at {kb(size)}"
        for key in ORDER
        for size, run in runs_of(document, key).items()
        if run.get("stopped_early")
    ]
    if stopped:
        out.append(
            "A run stops making calls after "
            f"{document['settings'].get('max_run_s', 600):.0f} seconds. These did: "
            + ", ".join(stopped)
            + ". Their figures are of the calls that were made."
        )
    unquiet = [
        document["targets"][key]["label"]
        for key in ORDER
        if key in document["targets"]
        and (document["targets"][key].get("conditions") or {}).get("quiet") is False
    ]
    if unquiet:
        out.append("The host was not idle enough before: " + ", ".join(unquiet) + ".")
    return [f"- {line}" for line in out]


def incomplete_text(document: Mapping[str, Any]) -> list[str]:
    """A warning, in front of everything, for a file the matrix did not finish."""
    if document.get("complete", True):
        return []
    error = document.get("error")
    return [
        "**Not complete**: the matrix ended before its last run"
        + (f" ({error})" if error else "")
        + ". The targets and payloads it did not reach are left out.",
        "",
    ]


def machine_text(machine: Mapping[str, Any], box: Mapping[str, Any]) -> str:
    """The machine, the Docker VM and the limits of the container, in a paragraph."""
    vm = machine.get("docker_vm") or {}
    text = (
        f"The machine: {machine['cpu']}, {machine['vcpus']} vCPUs, {gib(machine['ram_bytes'])} of "
        f"memory, {machine['os']}, Docker {machine['docker']} (its VM has {vm.get('cpus')} CPUs "
        f"and {gib(vm.get('memory_bytes'))}, {vm.get('os')}, {vm.get('architecture')})."
    )
    if box and box.get("cpus"):
        text += (
            f" The keystone container was limited to {box['cpus']:g} CPUs and "
            f"{gib(box.get('memory_bytes'))}, ran one uvicorn worker, and logged at warning level. "
            "The sandbox was off, and the rate limits were high enough that no call was refused."
        )
    return text


def render_section(document: Mapping[str, Any], source: Path | None = None) -> str:
    machine = document["machine"]
    settings = document["settings"]
    box = settings.get("container") or {}
    commit = str(machine.get("commit", ""))[:12]
    where = f"`{commit}` plus uncommitted changes" if machine.get("dirty") else f"`{commit}`"
    named = f"`{source}`" if source else "the result file"
    sizes = settings["sizes"]
    out = [
        "## Performance",
        "",
        f"Measured on {document['date']} at commit {where}, by `python -m eval.perf.matrix`. Every "
        f"number below is computed from {named}, which holds the latency of every call.",
        "",
        *incomplete_text(document),
        machine_text(machine, box),
        "",
        f"The run: {settings['sessions']} MCP sessions opened at once, each making "
        f"{settings['calls_each']} calls of the echo tool one after the other, with a payload of "
        + " or ".join(f"{kb(size)} (about {tokens_of(document, size):,} tokens)" for size in sizes)
        + " of English text. The timed calls start together, after each session has made 3 calls "
        "that are not counted. A call is timed from the request to the whole answer, and a call "
        "that fails is counted and timed like the others. The percentiles are nearest-rank: of "
        f"{settings['sessions'] * settings['calls_each']:,} calls the 95th is the "
        f"{int(settings['sessions'] * settings['calls_each'] * 0.95):,}th fastest. The generator "
        f"is {settings['processes']} processes, so that no one of them is the limit. The targets "
        "are the echo upstream alone, and Keystone in four settings of one build: passthrough "
        "(every slot a stub), full with the scanner off, full with the rules alone, and full with "
        "the classifier. Each was checked at `/metrics` before it was measured, and the model had "
        "loaded where there is one.",
        "",
        "### Against the targets",
        "",
        *verdicts(document),
        "",
    ]
    for size in sizes:
        out += [
            f"### {settings['sessions']} sessions, {settings['calls_each']} calls each, "
            f"{kb(size)} payload",
            "",
            latency_table(document, size, sequential=False),
            "",
        ]
    if settings.get("sequential_calls"):
        out += [
            f"### One session, {settings['sequential_calls']} calls, no queue",
            "",
            "The same targets with one session making its calls one after the other, so that "
            "nothing waits for another call. What a gateway adds here is what it needs, and what "
            "it adds with many sessions beyond this is the wait.",
            "",
        ]
        for size in sizes:
            out += [f"{kb(size)} payload:", "", latency_table(document, size, sequential=True), ""]
    stages = stage_table(document)
    if stages:
        out += [
            "### Where the time goes",
            "",
            "The mean time a call spent in each stage of the gateway during the timed calls, from "
            "`keystone_tool_call_duration_seconds`, in milliseconds. `total` is the time in the "
            "gateway, `upstream` the part of it spent waiting for the echo server, and the nine "
            "slots the rest. The client's mean is the generator's, which also has the wait for "
            "the event loop. At the sessions below every stage includes the time its call waited "
            "for the single event loop to come back to it.",
            "",
            *stages,
            "",
        ]
    alone = stage_table(document, sequential=True)
    if alone:
        out += [
            "With one session and no queue, the same counters are the work each stage does:",
            "",
            *alone,
            "",
        ]
    out += [
        "### What the numbers say",
        "",
        *reading(document),
        "",
        "### The conditions of the runs",
        "",
        conditions_table(document),
        "",
        "The host is idle when little else runs on it: the table says how idle it was in the two "
        "seconds before the target was measured, the CPU the container used while the calls were "
        "made (400% is the 4 CPUs it was limited to), and how busy the busiest process of the "
        "generator was (100% is one CPU).",
    ]
    return "\n".join(out).rstrip() + "\n"


# -- the document


def update_document(path: Path, section: str) -> None:
    """Put `section` between the markers of the document, or at its end."""
    block = f"{START}\n{section.rstrip()}\n{END}\n"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    if START in text:
        head, _, rest = text.partition(START)
        if END not in rest:
            raise ValueError(f"{path.name} has the start marker of the section and not its end")
        _, _, tail = rest.partition(END)
        path.write_text(head + block + tail.lstrip("\n"), encoding="utf-8")
        return
    path.write_text(text.rstrip("\n") + ("\n\n" if text else "") + block, encoding="utf-8")


def section_in(text: str) -> str | None:
    if START not in text or END not in text:
        return None
    return text.partition(START)[2].partition(END)[0].strip()


def short(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return path.name


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the performance section of docs/results.md")
    parser.add_argument("file", nargs="?", type=Path, help="a result file (default: the newest)")
    parser.add_argument("--doc", type=Path, default=RESULTS_DOC)
    parser.add_argument("--check", action="store_true", help="compare, and write nothing")
    args = parser.parse_args(argv)

    found = find_files()
    if args.file is None and not found:
        print("there is no result file: run python -m eval.perf.matrix", file=sys.stderr)
        return 2
    path: Path = args.file or found[-1]
    section = render_section(load(path), Path(short(path)))
    if args.check:
        text = args.doc.read_text(encoding="utf-8") if args.doc.is_file() else ""
        if section_in(text) == section.strip():
            print("docs/results.md is what the result file renders")
            return 0
        print("docs/results.md is not what the result file renders", file=sys.stderr)
        return 1
    update_document(args.doc, section)
    print(f"wrote the performance section of {short(args.doc)} from {short(path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
