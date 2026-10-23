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
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from collections.abc import Callable
from functools import partial
from pathlib import Path

from examples.injections import strip_markers
from keystone.core.types import ToolResult
from keystone.defense.scanner import CompositeScanner, build_scanner, extract
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--runs", type=int, default=300)
    args = parser.parse_args(argv)

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
