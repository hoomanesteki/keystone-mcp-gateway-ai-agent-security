#!/usr/bin/env python3
"""Measure how long the scanner takes to read a tool output.

    uv run python scripts/bench_scanner.py [--runs 300]

It times `CompositeScanner.scan_text` (the rules, NFKC and the label) on texts of several sizes,
made from the fixture mail and pages that this repository ships, so the words are ordinary and the
patterns have something to look at. Each size is also timed with an injection in the middle, because
a text with hits costs more than one without. The last rows time `extract` plus the scan on a result
that is JSON, the way an object from a tool arrives. The numbers in docs/spikes/scanner.md come
from here. Run it on a quiet machine: another process doubles the figures.

A token is taken as four characters, which is only a way to name the size and its bucket.

With `--classifier` it also loads the classifier (the extra `keystone[scanner]`; the first run
downloads the model) and times it alone and behind the rules, on the same texts, and counts the
runs that would have been left out by the timeout (`scanner.classifier_timeout_ms`). With `--scores`
it prints what the rules and the classifier make of each planted attack, the seeded mail and the
pages. That table is a look at the fixtures, not the detector evaluation (KS-707).
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from collections.abc import Awaitable, Callable
from functools import partial
from pathlib import Path

import anyio

from examples.injections import load, render, strip_markers
from keystone.core.types import ToolRef, ToolResult
from keystone.defense.classifier import HFClassifier, load_classifier
from keystone.defense.scanner import CompositeScanner, ScanDetails, build_scanner, extract
from keystone.settings import ScannerSettings

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples" / "fixtures"
WARMUP = 50
CHARS_PER_TOKEN = 4
SIZES = (400, 1_600, 4_000, 10_240, 40_000, 200_000)


def corpus() -> list[str]:
    """Benign paragraphs: the seeded mail, the benign pages and the seeded files."""
    texts: list[str] = []
    for mail in json.loads((FIXTURES / "mailbox.json").read_text()):
        texts.append(f"{mail['subject']}\n{mail['body']}")
    for page in json.loads((FIXTURES / "web" / "pages.json").read_text()):
        if not page["poisoned"]:
            texts.append(page["text"])
    for path in sorted((FIXTURES / "files").rglob("*.*")):
        texts.append(path.read_text())
    return texts


def text_of(size: int, paragraphs: list[str]) -> str:
    out: list[str] = []
    i = 0
    while sum(len(p) + 2 for p in out) < size:
        out.append(paragraphs[i % len(paragraphs)])
        i += 1
    return "\n\n".join(out)[:size]


def with_injection(text: str) -> str:
    demo = json.loads((FIXTURES / "injections" / "mailbox-poisoned.json").read_text())[0]
    injected = strip_markers(demo["body"])
    middle = len(text) // 2
    return text[:middle] + "\n\n" + injected + "\n\n" + text[middle:]


def percentile(samples: list[float], p: float) -> float:
    """`samples` is sorted."""
    return samples[int(p / 100 * (len(samples) - 1))]


def time_it(fn: Callable[[], object], runs: int) -> list[float]:
    for _ in range(WARMUP):
        fn()
    samples = []
    for _ in range(runs):
        started = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()
    return samples


def bucket(chars: int) -> str:
    """The length buckets of the detector evaluation (KS-707), in tokens."""
    tokens = chars // CHARS_PER_TOKEN
    return "<500" if tokens < 500 else "500-2000" if tokens <= 2000 else ">2000"


def row(label: str, chars: int, samples: list[float], extra: str = "") -> str:
    return (
        f"{label:34} {chars:>8} {bucket(chars):>9} "
        f"{statistics.median(samples):>8.3f} {percentile(samples, 95):>8.3f} "
        f"{percentile(samples, 99):>8.3f} {extra}"
    )


async def time_async(
    fn: Callable[[], Awaitable[object]], runs: int, warmup: int = 3
) -> tuple[list[float], list[float]]:
    """Wall-clock milliseconds and CPU milliseconds (all threads of the process) of each run. On a
    machine that is busy with other things the wall clock moves with the load and the CPU time
    does not, so both are shown."""
    for _ in range(warmup):
        await fn()
    wall, cpu = [], []
    for _ in range(runs):
        started, used = time.perf_counter(), time.process_time()
        await fn()
        wall.append((time.perf_counter() - started) * 1000)
        cpu.append((time.process_time() - used) * 1000)
    return sorted(wall), sorted(cpu)


async def classifier_rows(runs: int, timeout_ms: int) -> None:
    loaded_at = time.perf_counter()
    classifier = load_classifier(ScannerSettings())
    if not isinstance(classifier, HFClassifier):
        print("no classifier: install the extra with `uv sync --extra scanner`")
        return
    await classifier.warm()
    print(f"model loaded in {time.perf_counter() - loaded_at:.1f} s ({classifier.name})")
    # The first calls after a load are slow (kernels and buffers are made on first use), so a
    # model that has just loaded is warmed on texts of three sizes before anything is timed.
    paragraphs = corpus()
    for size in (400, 1_600, 4_000):
        for _ in range(3):
            await classifier.score(text_of(size, paragraphs))
    print(
        f"{'text':24} {'chars':>7} {'tokens':>9} {'wall p50':>9} {'wall p95':>9} "
        f"{'cpu p50':>8}  over {timeout_ms} ms"
    )
    scanner = build_scanner(ScannerSettings(classifier_timeout_ms=10_000), classifier)
    for size in (*SIZES[:-2], 20_000):
        text = text_of(size, paragraphs)
        wall, cpu = await time_async(partial(classifier.score, text), runs)
        late = sum(1 for ms in wall if ms > timeout_ms)
        print(
            f"{'classifier alone':24} {len(text):>7} {bucket(len(text)):>9} "
            f"{statistics.median(wall):>9.0f} {percentile(wall, 95):>9.0f} "
            f"{statistics.median(cpu):>8.0f}  {late}/{runs}"
        )
        tool = ToolRef.model_construct()
        wall, cpu = await time_async(partial(scanner.scan, text, tool=tool), runs)
        print(
            f"{'rules and classifier':24} {len(text):>7} {bucket(len(text)):>9} "
            f"{statistics.median(wall):>9.0f} {percentile(wall, 95):>9.0f} "
            f"{statistics.median(cpu):>8.0f}"
        )


async def score_rows() -> None:
    classifier = load_classifier(ScannerSettings())
    if isinstance(classifier, HFClassifier):
        await classifier.warm()
    scanner = build_scanner(ScannerSettings(classifier_timeout_ms=10_000), classifier)
    tool = ToolRef.model_construct()
    templates, goals = load()
    texts: list[tuple[str, str]] = []
    goal = next(g for g in goals if g.id == "forward_invoice")
    beacon = next(g for g in goals if g.id == "beacon")
    for template in templates:
        texts.append((f"{template.id}, forward the invoice", render(template, goal, marker=False)))
        texts.append((f"{template.id}, open a web address", render(template, beacon, marker=False)))
    mails = json.loads((FIXTURES / "injections" / "mailbox-poisoned.json").read_text())
    texts += [(f"poisoned mail {m['id']}", strip_markers(m["body"])) for m in mails]
    for mail in json.loads((FIXTURES / "mailbox.json").read_text()):
        texts.append((f"seeded mail {mail['id']}", f"{mail['subject']}\n{mail['body']}"))
    for page in json.loads((FIXTURES / "web" / "pages.json").read_text()):
        kind = "poisoned page" if page["poisoned"] else "benign page"
        texts.append((f"{kind} {page['url'].split('//')[1][:34]}", strip_markers(page["text"])))
    print(f"{'text':58} {'rules':>6} {'model':>6} {'final':>6}  label")
    for label, text in texts:
        result = await scanner.scan(text, tool=tool)
        if not isinstance(result, ScanDetails):
            raise TypeError("the scanner returned a result without details")
        model = "-" if result.classifier_score is None else f"{result.classifier_score:.3f}"
        line = f"{label:58} {result.rule_score:>6.3f} {model:>6} {result.score:>6.3f}"
        print(f"{line}  {result.label}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--runs", type=int, default=300)
    parser.add_argument("--classifier", action="store_true", help="time the classifier too")
    parser.add_argument("--scores", action="store_true", help="print the score of each fixture")
    parser.add_argument("--classifier-runs", type=int, default=30)
    parser.add_argument(
        "--skip-rules", action="store_true", help="with --classifier: time only the model"
    )
    args = parser.parse_args(argv)
    if args.scores:
        anyio.run(score_rows)
        return 0
    if args.skip_rules and args.classifier:
        anyio.run(classifier_rows, args.classifier_runs, ScannerSettings().classifier_timeout_ms)
        return 0

    scanner: CompositeScanner = build_scanner(ScannerSettings(max_scan_chars=1_000_000))
    paragraphs = corpus()
    print(f"{platform.platform()}, Python {platform.python_version()}, {args.runs} runs each")
    print(f"{'text':34} {'chars':>8} {'tokens':>9} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8}")
    for size in SIZES:
        benign = text_of(size, paragraphs)
        samples = time_it(partial(scanner.scan_text, benign), args.runs)
        print(row("rules, no hit", len(benign), samples))
        injected = with_injection(benign)
        label = scanner.scan_text(injected).label
        samples = time_it(partial(scanner.scan_text, injected), args.runs)
        print(row("rules, injection in the middle", len(injected), samples, f"({label})"))
    # An object from a tool arrives as JSON text: extract reads the strings in it, then the scan.
    body = text_of(10_240, paragraphs)
    result = ToolResult(content=[{"type": "text", "text": json.dumps({"id": "m1", "body": body})}])

    def whole() -> None:
        scanner.scan_text(extract(result).text)

    print(row("extract and rules, JSON, no hit", len(body), time_it(whole, args.runs)))
    # The limit: a text longer than scanner.max_scan_chars is read at both ends.
    capped = build_scanner(ScannerSettings())
    huge = text_of(2_000_000, paragraphs)
    samples = time_it(partial(capped.scan_text, huge), max(args.runs // 10, 10))
    print(row("rules, 2 MB cut to the limit", len(huge), samples))
    if args.classifier:
        anyio.run(classifier_rows, args.classifier_runs, ScannerSettings().classifier_timeout_ms)
    return 0


if __name__ == "__main__":
    sys.exit(main())
