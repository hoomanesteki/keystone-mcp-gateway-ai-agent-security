"""docs/results.md and the README quote numbers. These tests recompute them from the raw files in
eval/results/ and fail when a quoted number drifts from its source."""

import json
import re
from pathlib import Path

import pytest

from eval.detector.metrics import percentile

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "eval" / "results"
DOC = (ROOT / "docs" / "results.md").read_text()
README = (ROOT / "README.md").read_text()


def section(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


def rows(text: str) -> list[list[str]]:
    return [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in text.splitlines()
        if line.startswith("|") and not set(line) <= set("|- ")
    ]


def redteam_counts(path: Path) -> tuple[int, int, int, int]:
    """Attacks landed, attacks, benign tasks done, benign tasks."""
    runs = [json.loads(line) for line in path.read_text().splitlines() if line]
    runs = [run for run in runs if run["type"] == "run"]
    attacks = [run for run in runs if run["kind"] == "attack"]
    benign = [run for run in runs if run["kind"] == "benign"]
    return (
        sum(1 for run in attacks if run["attack_success"]),
        len(attacks),
        sum(1 for run in benign if run["utility_success"] or run["stopped"] == "done"),
        len(benign),
    )


@pytest.mark.phase(9)
def test_results_numbers_match_raw() -> None:
    red = section(DOC, "<!-- detector:end -->", "<!-- redteam:end -->")
    sources = {
        row[0].strip("`"): row[1]
        for row in rows(section(red, "### Where the numbers come from", "<!--"))[1:]
    }
    assert len(sources) >= 10

    table = rows(section(red, "### Attack success and utility", "ASR is"))[1:]
    checked = 0
    for agent, config, landed, *_ in table:
        if agent != "Naive":
            continue
        files = [Path(ROOT / name) for name, label in sources.items() if label == config]
        assert files, config
        counts = {redteam_counts(file)[:2] for file in files}
        assert len(counts) == 1, f"{config}: repeat runs disagree on attacks landed: {counts}"
        won, total = counts.pop()
        assert landed == f"{won} of {total}", config
        checked += 1
    assert checked == 5

    perf = json.loads((RESULTS / "perf-2026-10-24b.json").read_text())
    text = section(DOC, "<!-- perf:start -->", "<!-- perf:end -->")
    names = {
        "direct": "Direct echo",
        "passthrough": "Keystone passthrough",
        "scanner-off": "Keystone full, scanner off",
        "rules-only": "Keystone full, rules only",
        "classifier": "Keystone full, classifier",
    }
    for key, label in names.items():
        for run in perf["targets"][key]["runs"]:
            ok = [x for x in run["latencies_ms"]]
            p50, p95 = percentile(ok, 50), percentile(ok, 95)
            heading = f"### 200 sessions, 20 calls each, {run['size'] // 1024} KB payload"
            block = text.split(heading, 1)[1].split("###", 1)[0]
            row = next(r for r in rows(block) if r[0] == label)
            assert row[1] == f"{p50:.1f}", (key, run["size"])
            assert row[2] == f"{p95:.1f}", (key, run["size"])
            if key == "scanner-off" and run["size"] == 1024:
                direct = next(r for r in perf["targets"]["direct"]["runs"] if r["size"] == 1024)
                added50 = p50 - percentile(direct["latencies_ms"], 50)
                added95 = p95 - percentile(direct["latencies_ms"], 95)
                for quoted in (f"p50 +{added50:.1f} ms", f"p95 +{added95:.1f} ms"):
                    assert quoted in README
                    assert quoted in DOC


@pytest.mark.phase(9)
def test_detector_recall_matches_raw() -> None:
    raw = json.loads((RESULTS / "detector-2026-10-24.json").read_text())["result"]["configs"]
    for key, label in [
        ("rules", "Rules"),
        ("classifier", "Model, windows of 128"),
        ("combined", "Rules first, then the model"),
    ]:
        recall = raw[key]["recall_at_fpr_5pct"]["recall"]
        low, high = raw[key]["recall_at_fpr_5pct"]["recall_ci95"]
        expected = f"{recall:.2f} (95% {low:.2f} to {high:.2f})"
        line = next(
            row
            for row in rows(section(DOC, "### How good the scores are", "Recall at a fixed"))
            if row[0] == label
        )
        assert line[1].startswith(expected), (label, line[1])
    combined = raw["combined"]["recall_at_fpr_5pct"]["recall"]
    assert f"{combined:.2f}" in README


@pytest.mark.phase(9)
def test_readme_quotes_the_red_team_counts() -> None:
    c0 = redteam_counts(RESULTS / "redteam-naive-C0-2026-10-24.jsonl")
    c2 = redteam_counts(RESULTS / "redteam-naive-C2-2026-10-24-repeat2.jsonl")
    assert c0[:2] == (48, 48)
    assert c2[:2] == (0, 48)
    assert "0 of 48" in README
    assert "48 of 48" in README
    for sentence in re.findall(r"(\d+) of 48", README):
        assert sentence in {"0", "36", "48", "8", "29"}, sentence
