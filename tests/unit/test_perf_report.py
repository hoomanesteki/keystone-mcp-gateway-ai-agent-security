"""KS-903: the words and the verdicts of the performance report.

The result file here is made by hand and small, so that each figure the report computes can be
checked with a pencil. The report reads a file and nothing else, and these tests give it nothing
else.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from eval.perf import report
from eval.perf.report import (
    END,
    START,
    added,
    generator_busy,
    kinds_text,
    load,
    render_section,
    runs_of,
    section_in,
    summary_of,
    tokens_of,
    update_document,
    verdicts,
)

pytestmark = pytest.mark.phase(9)

ROOT = Path(__file__).resolve().parents[2]
SIZES = [1024, 8192]


def run(
    size: int,
    latency_ms: float,
    *,
    calls: int = 100,
    sessions: int = 10,
    errors: int = 0,
    stages: dict[str, float] | None = None,
    stopped_early: bool = False,
    cpu_percent: float | None = None,
) -> dict[str, Any]:
    """A run in which every call took `latency_ms`, and the calls took one second in all."""
    latencies = [latency_ms] * calls
    return {
        "size": size,
        "sessions": sessions,
        "calls_each": calls // sessions,
        "summary": {"wall_s": 1.0, "errors": errors},
        "errors": {},
        "opened": sessions,
        "stopped_early": stopped_early,
        "generator": [{"wall_s": 1.0, "cpu_s": 0.25}, {"wall_s": 1.0, "cpu_s": 0.4}],
        "stages": {
            name: {"mean_ms": mean, "calls": calls} for name, mean in (stages or {}).items()
        },
        "container": (
            None
            if cpu_percent is None
            else {
                "samples": 5,
                "cpu_percent_mean": cpu_percent,
                "cpu_percent_max": cpu_percent + 20,
                "memory_mib_max": 900.0,
            }
        ),
        "latencies_ms": latencies,
    }


def target(label: str, by_size: dict[int, float], alone: dict[int, float], **more: Any) -> Any:
    return {
        "label": label,
        "gateway": more.pop("gateway", None),
        "conditions": {"idle_percent": 93.0, "waited_s": 2.0, "quiet": True},
        "runs": [run(size, ms, **more) for size, ms in by_size.items()],
        "sequential": [
            run(size, ms, calls=50, sessions=1, **{k: v for k, v in more.items() if k == "stages"})
            for size, ms in alone.items()
        ],
    }


def document(
    off: dict[int, float] | None = None, classifier: dict[int, float] | None = None
) -> dict[str, Any]:
    """Direct echo at 10 ms. Scanner off adds `off` less 10, the classifier `classifier` less 10."""
    stages = {"total": 8.0, "upstream": 3.0, "pinning": 1.0, "policy": 0.5, "output_scan": 0.1}
    return {
        "version": 1,
        "date": "2026-10-25",
        "machine": {
            "cpu": "Test CPU",
            "vcpus": 8,
            "ram_bytes": 16 * 2**30,
            "os": "TestOS-1",
            "docker": "29.0",
            "docker_vm": {
                "cpus": 8,
                "memory_bytes": 8 * 2**30,
                "os": "Docker Test",
                "architecture": "x",
            },
            "commit": "0123456789abcdef0123456789abcdef01234567",
            "dirty": False,
        },
        "settings": {
            "sessions": 10,
            "calls_each": 10,
            "sequential_calls": 50,
            "sizes": SIZES,
            "processes": 2,
            "max_run_s": 600.0,
            "payload_tokens": {"1024": 197, "8192": 1580},
            "container": {"cpus": 4.0, "memory_bytes": 4 * 2**30},
        },
        "targets": {
            "direct": target("Direct echo", {1024: 10.0, 8192: 12.0}, {1024: 3.0, 8192: 4.0}),
            "passthrough": target(
                "Keystone passthrough",
                {1024: 14.0, 8192: 16.0},
                {1024: 6.0, 8192: 7.0},
                stages=stages,
            ),
            "scanner-off": target(
                "Keystone full, scanner off",
                off or {1024: 18.0, 8192: 20.0},
                {1024: 9.0, 8192: 10.0},
                stages=stages,
                cpu_percent=95.0,
            ),
            "rules-only": target(
                "Keystone full, rules only",
                {1024: 19.0, 8192: 22.0},
                {1024: 10.0, 8192: 11.0},
                stages={**stages, "output_scan": 0.3},
            ),
            "classifier": target(
                "Keystone full, classifier",
                classifier or {1024: 150.0, 8192: 300.0},
                {1024: 120.0, 8192: 200.0},
                stages={**stages, "output_scan": 90.0, "total": 100.0},
                cpu_percent=380.0,
            ),
        },
    }


def test_the_added_latency_is_the_target_less_the_upstream_at_each_percentile() -> None:
    doc = document()

    extra = added(doc, "scanner-off", 1024)

    assert extra == {"p50_ms": 8.0, "p95_ms": 8.0, "p99_ms": 8.0}
    assert added(doc, "scanner-off", 8192) == {"p50_ms": 8.0, "p95_ms": 8.0, "p99_ms": 8.0}
    assert added(doc, "scanner-off", 1024, sequential=True) == {
        "p50_ms": 6.0,
        "p95_ms": 6.0,
        "p99_ms": 6.0,
    }
    assert added(doc, "no-such-target", 1024) is None
    assert added(doc, "scanner-off", 4096) is None


def test_the_summary_is_computed_again_from_the_latencies_of_the_file() -> None:
    doc = document()
    # The summary the matrix wrote is not trusted: the figures come from the latencies.
    doc["targets"]["direct"]["runs"][0]["latencies_ms"] = [float(n) for n in range(1, 101)]

    summary = summary_of(doc["targets"]["direct"]["runs"][0])

    assert (summary["p50_ms"], summary["p95_ms"], summary["p99_ms"]) == (50.0, 95.0, 99.0)
    assert summary["throughput"] == 100.0


def test_m5_is_met_when_the_scanner_off_gateway_adds_under_10_and_25_ms_at_both_sizes() -> None:
    doc = document(off={1024: 19.0, 8192: 19.5})

    [table] = verdicts(doc)

    m5 = next(line for line in table.splitlines() if line.startswith("| M5"))
    assert "p50 at most 10 ms, p95 at most 25 ms" in m5
    assert "1 KB: p50 +9.0 ms, p95 +9.0 ms; 8 KB: p50 +7.5 ms, p95 +7.5 ms" in m5
    assert m5.endswith("| met |")


def test_m5_is_not_met_if_either_size_misses() -> None:
    doc = document(off={1024: 19.0, 8192: 40.0})

    [table] = verdicts(doc)

    m5 = next(line for line in table.splitlines() if line.startswith("| M5"))
    assert m5.endswith("| not met |")


def test_m6_is_judged_at_the_sizes_of_2000_tokens_or_fewer_and_on_the_p95() -> None:
    # 1 KB is 197 tokens and 8 KB is 1,580, so both count. The p95 added is 140 and 290 ms.
    doc = document()

    [table] = verdicts(doc)

    m6 = next(line for line in table.splitlines() if line.startswith("| M6"))
    assert "1 KB (197 tokens): p95 +140.0 ms; 8 KB (1580 tokens): p95 +288.0 ms" in m6
    assert m6.endswith("| not met |")
    met = document(classifier={1024: 100.0, 8192: 120.0})
    again = next(row for row in verdicts(met)[0].splitlines() if row.startswith("| M6"))
    assert again.endswith("| met |")


def test_a_payload_over_2000_tokens_is_left_out_of_m6() -> None:
    doc = document()
    doc["settings"]["payload_tokens"]["8192"] = 2100

    [table] = verdicts(doc)

    m6 = next(line for line in table.splitlines() if line.startswith("| M6"))
    assert "8 KB" not in m6 and "1 KB (197 tokens)" in m6
    assert tokens_of(doc, 8192) == 2100
    # A file that does not count the tokens gets the guess of four bytes a token.
    del doc["settings"]["payload_tokens"]
    assert tokens_of(doc, 8192) == 2048


def test_the_section_has_the_targets_the_tables_and_the_reading() -> None:
    section = render_section(document(), Path("eval/results/perf-2026-10-25.json"))

    assert section.startswith("## Performance\n")
    assert "Measured on 2026-10-25 at commit `0123456789ab`" in section
    assert "`eval/results/perf-2026-10-25.json`" in section
    assert "Test CPU, 8 vCPUs, 16 GB of memory, TestOS-1, Docker 29.0" in section
    assert "limited to 4 CPUs and 4 GB" in section
    assert "### 10 sessions, 10 calls each, 1 KB payload" in section
    assert "### 10 sessions, 10 calls each, 8 KB payload" in section
    assert (
        "| Keystone full, scanner off | 18.0 | 18.0 | 18.0 | +8.0 | +8.0 | +8.0 | 100 | 0 of 100 |"
        in section
    )
    assert "| Direct echo | 10.0 | 10.0 | 10.0 | - | - | - | 100 | 0 of 100 |" in section
    assert "### One session, 50 calls, no queue" in section
    assert "### Where the time goes" in section and "### The conditions of the runs" in section
    # The stage table: the mean time in each stage, per target.
    assert "| Keystone full, scanner off | 1 KB | 18.0 | 8.0 | 3.0 |" in section
    assert (
        "- At 10 sessions the echo upstream alone serves 100 calls a second at a median of 10.0 ms"
        in section
    )
    assert (
        "the keystone container used 95% of CPU on average, of the 400% it was allowed. One event "
        "loop on one core can use about 100%." in section
    )
    assert "the largest of them `pinning` at 1.0 ms" in section
    assert "With one session and no queue the scanner-off gateway adds p50 6.0 ms" in section
    assert (
        "With one session the scan took 90.0 ms on average with the classifier and 0.3 ms with the "
        "rules alone at 1 KB, and 90.0 ms with the classifier at 10 sessions." in section
    )
    # 95% of a CPU for one second, over the 100 calls made in it.
    assert "That is 9.5 ms of CPU for each call made, those that failed included." in section


def test_the_wait_is_called_a_queue_only_if_more_sessions_hardly_add_to_the_calls_a_second() -> (
    None
):
    # One session makes 50 calls in a second and ten make 100: twice as many, so no queue is said.
    many = report.reading(document())
    [scaling] = [line for line in many if line.startswith("- One session alone makes")]

    assert scaling == (
        "- One session alone makes 50.0 calls a second through the scanner-off gateway and 10 "
        "sessions make 100.0, 100% more. 10 sessions that call one after the other wait for each "
        "call 10 / 100.0 = 0.10 s on average, and the clients measured a mean of 0.02 s."
    )
    assert "one event loop and not the work" not in scaling

    # One session makes 50 calls in 0.6 s (83.3 a second); ten make 100 in a second, 20% more.
    doc = document()
    doc["targets"]["scanner-off"]["sequential"][0]["summary"]["wall_s"] = 0.6
    [queued] = [line for line in report.reading(doc) if line.startswith("- One session alone")]

    assert "makes 83.3 calls a second" in queued and "100.0, 20% more." in queued
    assert queued.endswith(
        " The other 9 sessions added little to what the gateway serves, so what it adds at 10 "
        "sessions is the wait for one event loop and not the work of a call."
    )


def test_the_queue_is_left_out_if_the_scanner_off_target_was_not_run_alone() -> None:
    doc = document()
    doc["targets"]["scanner-off"]["sequential"] = []

    lines = report.reading(doc)

    assert not any(line.startswith("- One session alone makes") for line in lines)


def test_the_conditions_say_how_idle_the_host_was_and_how_busy_the_container_and_generator() -> (
    None
):
    section = render_section(document())

    assert (
        "| Keystone full, scanner off | 1 KB | 93% | 95% | 115% | 900 | 40% of a CPU |" in section
    )
    assert generator_busy(document()["targets"]["direct"]["runs"][0]) == pytest.approx(0.4)


def test_a_run_that_was_cut_short_and_a_host_that_was_not_quiet_are_said() -> None:
    doc = document()
    doc["targets"]["classifier"]["runs"][1]["stopped_early"] = True
    doc["targets"]["rules-only"]["runs"][1]["conditions"] = {"idle_percent": 40.0, "quiet": False}

    section = render_section(doc)

    assert (
        "A run stops making calls after 600 seconds. These did: Keystone full, classifier at 8 KB."
        in section
    )
    assert "The host was not idle enough before: Keystone full, rules only at 8 KB." in section


def test_a_target_that_was_not_run_is_left_out_and_not_filled_in() -> None:
    doc = document()
    del doc["targets"]["rules-only"]
    del doc["targets"]["classifier"]

    section = render_section(doc)

    assert "rules only" not in section.lower()
    [table] = verdicts(doc)
    m6 = next(line for line in table.splitlines() if line.startswith("| M6"))
    assert "not measured" in m6 and m6.endswith("|  |")  # no verdict without a measurement
    assert "None" not in section and "nan" not in section.lower()


def test_a_file_the_matrix_did_not_finish_says_so_in_front_of_everything() -> None:
    doc = document()
    doc["complete"] = False
    doc["error"] = "TimeoutError: a load process did not answer"
    del doc["targets"]["classifier"]

    section = render_section(doc)

    assert (
        "**Not complete**: the matrix ended before its last run (TimeoutError: a load process"
        in (section.split("### Against the targets")[0])
    )
    assert "Keystone full, classifier" not in section
    complete = dict(document(), complete=True)
    assert "Not complete" not in render_section(complete)
    assert "Not complete" not in render_section(document())  # an older file has no flag


def test_the_text_follows_the_voice_rules() -> None:
    import lint_prose

    section = render_section(document())

    assert chr(0x2014) not in section
    for label, pattern in lint_prose.BANNED_RE:
        assert not pattern.search(section), label
    assert "None" not in section


def test_the_section_goes_between_its_markers_and_leaves_the_rest_alone(tmp_path: Path) -> None:
    doc = tmp_path / "results.md"
    doc.write_text("# Results\n\n<!-- redteam:start -->\n## Red team\n<!-- redteam:end -->\n")

    update_document(doc, "## Performance\n\nfirst\n")
    update_document(doc, "## Performance\n\nsecond\n")

    text = doc.read_text()
    assert text.count(START) == 1 and text.count(END) == 1
    assert "first" not in text and "second" in text
    assert text.startswith("# Results\n\n<!-- redteam:start -->\n## Red team\n<!-- redteam:end -->")
    assert section_in(text) == "## Performance\n\nsecond"


def test_a_marker_without_its_end_is_an_error_and_not_a_lost_document(tmp_path: Path) -> None:
    doc = tmp_path / "results.md"
    doc.write_text(f"# Results\n\n{START}\nhalf\n")

    with pytest.raises(ValueError, match="not its end"):
        update_document(doc, "## Performance\n")

    assert doc.read_text().endswith("half\n")


def test_the_check_compares_the_document_with_what_the_file_renders(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = tmp_path / "perf-2026-10-25.json"
    result.write_text(json.dumps(document()), encoding="utf-8")
    doc = tmp_path / "results.md"

    assert report.main([str(result), "--doc", str(doc), "--check"]) == 1
    assert report.main([str(result), "--doc", str(doc)]) == 0
    assert report.main([str(result), "--doc", str(doc), "--check"]) == 0

    doc.write_text(doc.read_text().replace("Performance", "Performance, edited by hand"))
    assert report.main([str(result), "--doc", str(doc), "--check"]) == 1
    assert "is not what the result file renders" in capsys.readouterr().err


def test_the_runs_of_a_target_are_found_by_size() -> None:
    doc = document()

    assert sorted(runs_of(doc, "direct")) == SIZES
    assert sorted(runs_of(doc, "direct", sequential=True)) == SIZES
    assert runs_of(doc, "nothing") == {}


def test_the_committed_document_is_what_the_report_renders_from_the_committed_file() -> None:
    files = report.find_files()
    text = (ROOT / "docs" / "results.md").read_text(encoding="utf-8")

    if not files:
        assert section_in(text) is None or START not in text
        return
    # A hand edit of the document, or of the file, or of the code that words it, shows here.
    # `python -m eval.perf.report` writes the document again.
    newest = files[-1]
    before = load(files[-2]) if len(files) > 1 else None
    rendered = render_section(load(newest), Path(report.short(newest)), before)
    assert section_in(text) == rendered.strip()
    if before is not None:
        kept = report.render_previous(before, Path(report.short(files[-2])))
        assert section_in(text, report.PREVIOUS_START, report.PREVIOUS_END) == kept.strip()


def test_what_failed_is_listed_with_where_it_began_and_the_events_the_gateway_logged() -> None:
    doc = document()
    run_ = doc["targets"]["scanner-off"]["runs"][0]
    run_["summary"]["errors"] = 10
    run_["errors"] = {"tool error KS_DENIED: session state is unavailable": 6, "ReadTimeout": 4}
    run_["log_events"] = {"session_store_failed (MaxConnectionsError)": 10, "other_event": 1}
    run_["failed_calls"] = [1] * 8 + [2, 3]
    run_["failed_at_s"] = [0.0] * 7 + [1.5, 5.0, 9.0]

    section = render_section(doc)

    assert "### What failed" in section
    # 100 calls succeeded and 10 failed: 10 of 110.
    assert (
        "| Keystone full, scanner off | 1 KB | 6 tool error KS_DENIED: session state is "
        "unavailable; 4 ReadTimeout | 9.1% | 8 of 10 were a first call; 8 began in the first "
        "2 s | 10 session_store_failed (MaxConnectionsError); 1 other_event |"
    ) in section
    assert (
        "In the runs where a tenth of the calls or fewer failed, 8 of the 10 failures were the "
        "first call of a session and 8 began in the first two seconds: the sessions start "
        "together, and their first calls arrive at once." in section
    )
    # No failure, no section.
    assert "### What failed" not in render_section(document())


def test_the_commonest_kinds_of_failure_are_shown_and_the_rest_counted() -> None:
    kinds = {"a": 5, "b": 9, "c": 1, "d": 2, "e": 3}

    assert kinds_text(kinds) == "9 b; 5 a; 3 e; 3 of 2 other kinds"
    assert kinds_text({"x": 1}) == "1 x"
    assert kinds_text({}) == "none"


# -- KS-992: the single-session rows, the model's share, and the measurement before


def test_the_verdicts_also_judge_one_session_with_no_queue() -> None:
    # The scanner-off gateway adds 9 ms at one session and 8 ms at ten; the classifier 117 ms.
    doc = document()

    [table] = verdicts(doc)
    rows = {line.split("|")[1].strip(): line for line in table.splitlines()[2:]}

    assert list(rows) == ["M5", "M6", "M5, one session", "M6, one session"]
    assert (
        "1 KB: p50 +6.0 ms, p95 +6.0 ms; 8 KB: p50 +6.0 ms, p95 +6.0 ms" in rows["M5, one session"]
    )
    assert rows["M5, one session"].endswith("| met |")
    assert (
        "1 KB (197 tokens): p95 +117.0 ms; 8 KB (1580 tokens): p95 +196.0 ms"
        in rows["M6, one session"]
    )
    assert rows["M6, one session"].endswith("| not met |")


def test_what_the_model_did_is_shown_when_the_build_counted_it() -> None:
    doc = document()
    run_ = runs_of(doc, "classifier")[1024]
    run_["models"] = {"answered": 25.0, "busy": 70.0, "timeout": 5.0}

    section = render_section(doc)

    assert "### What the model did" in section
    assert "| 10 sessions | 1 KB | 25% | 0 | 5% | 70% | 0 | 100 |" in section
    assert "the model scored 25% of the scans and was left out of 70%" in section
    assert "### What the model did" not in render_section(document())


def test_the_section_compares_the_calls_a_second_of_one_process_with_the_measurement_before() -> (
    None
):
    before = document()
    before["machine"]["commit"] = "fedcba9876543210"
    # Before, the gateway served 50 calls a second at ten sessions and 40 with one.
    runs_of(before, "scanner-off")[1024]["summary"]["wall_s"] = 2.0
    runs_of(before, "scanner-off", sequential=True)[1024]["summary"]["wall_s"] = 1.25
    doc = document()

    section = render_section(doc, previous=before)

    assert (
        "serves 50.0 calls a second with one session and 100.0 with 10 sessions. In the "
        "measurement before this one (commit `fedcba987654`) it was 40.0 and 50.0." in section
    )
    # 10 sessions, a median of 10 ms for the upstream alone and 10 ms allowed on top of it.
    assert "the gateway would have to serve about 500 calls a second" in section
    assert "which is one core" in section


def test_the_measurement_before_is_kept_with_its_commit_and_its_headline_tables() -> None:
    before = document()
    before["machine"]["commit"] = "fedcba9876543210"

    kept = report.render_previous(before, Path("eval/results/perf-2026-10-24.json"))

    assert "### The measurement before this one (commit `fedcba987654`, 2026-10-25)" in kept
    assert "`eval/results/perf-2026-10-24.json`" in kept
    assert "| M5 |" in kept and "| M6 |" in kept
    assert "10 sessions, 10 calls each, 1 KB payload:" in kept
    assert "One session, 50 calls, 1 KB payload:" in kept
    assert "8 KB payload" not in kept


def test_the_check_and_the_writer_keep_both_measurements_in_the_document(tmp_path: Path) -> None:
    older = tmp_path / "perf-2026-10-24.json"
    newer = tmp_path / "perf-2026-10-25.json"
    first = document()
    first["machine"]["commit"] = "fedcba9876543210"
    older.write_text(json.dumps(first), encoding="utf-8")
    newer.write_text(json.dumps(document()), encoding="utf-8")
    doc = tmp_path / "results.md"
    doc.write_text("# Results\n\nBefore.\n", encoding="utf-8")

    assert report.main([str(newer), "--doc", str(doc)]) == 0

    text = doc.read_text(encoding="utf-8")
    assert text.startswith("# Results\n\nBefore.\n")
    assert text.index(START) < text.index(END) < text.index(report.PREVIOUS_START)
    assert report.PREVIOUS_END in text and "fedcba987654" in text
