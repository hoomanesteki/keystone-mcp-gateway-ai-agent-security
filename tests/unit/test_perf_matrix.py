"""KS-903: the parts of the performance matrix that need no stack.

Nothing here starts a container. The override file is read as the data it is, its variables are fed
to `Settings` the way compose would hand them to Keystone, and the commands the matrix would run
are captured and looked at.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from eval.perf import matrix
from eval.perf.matrix import (
    BY_KEY,
    TARGETS,
    Sampler,
    Target,
    configure,
    parse_stats,
    parse_top_idle,
    wait_until_quiet,
)
from keystone.settings import Settings

pytestmark = [pytest.mark.phase(9), pytest.mark.usefixtures("clean_env")]

ROOT = Path(__file__).resolve().parents[2]
OVERRIDE = yaml.safe_load((ROOT / "deploy" / "perf.override.yml").read_text())
SETTINGS = OVERRIDE["services"]["keystone"]["environment"]
CONFIG = ROOT / "deploy" / "keystone.compose.yaml"


def default_of(value: str) -> str:
    found = re.fullmatch(r"\$\{[A-Z_]+:-(.*)\}", value)
    assert found, value
    return found.group(1)


def variable_of(value: str) -> str:
    found = re.match(r"\$\{([A-Z_]+):-", value)
    assert found, value
    return found.group(1)


def settings_for(monkeypatch: pytest.MonkeyPatch, target: Target) -> Settings:
    """Keystone as compose starts it for a target: the config file, and the variables of the
    override with the target's values where it names them and their defaults elsewhere."""
    monkeypatch.setenv("KEYSTONE_CONFIG", str(CONFIG))
    for name, value in SETTINGS.items():
        if value.startswith("${"):
            monkeypatch.setenv(name, target.settings.get(variable_of(value), default_of(value)))
        else:
            monkeypatch.setenv(name, value)
    return Settings()


def test_the_targets_are_the_five_of_the_plan_in_order() -> None:
    assert [t.key for t in TARGETS] == [
        "direct",
        "passthrough",
        "scanner-off",
        "rules-only",
        "classifier",
    ]
    assert TARGETS[0].direct and not any(t.direct for t in TARGETS[1:])
    assert next(t.label for t in TARGETS) == "Direct echo"
    assert set(BY_KEY) == {t.key for t in TARGETS}


@pytest.mark.parametrize(
    ("key", "profile", "scanner", "classifier"),
    [
        ("passthrough", "passthrough", False, "protectai-deberta-v2"),
        ("scanner-off", "full", False, "protectai-deberta-v2"),
        ("rules-only", "full", True, "none"),
        ("classifier", "full", True, "protectai-deberta-v2"),
    ],
)
def test_the_settings_of_a_target_make_the_gateway_the_target_says_it_is(
    monkeypatch: pytest.MonkeyPatch, key: str, profile: str, scanner: bool, classifier: str
) -> None:
    built = settings_for(monkeypatch, BY_KEY[key])

    assert built.profile == profile
    # The gateway scans when its scanner is enabled and its profile is the full one.
    assert (built.scanner.enabled and built.profile == "full") is scanner
    assert built.scanner.classifier == classifier


def test_every_variable_a_target_sets_is_one_the_override_reads() -> None:
    read = {variable_of(v) for v in SETTINGS.values() if v.startswith("${PERF_")}

    for target in TARGETS:
        assert set(target.settings) <= read, target.key


def test_what_every_target_shares_is_the_4_cpus_the_4_gb_and_no_rate_limit_worth_the_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = OVERRIDE["services"]["keystone"]["deploy"]["resources"]["limits"]
    built = settings_for(monkeypatch, BY_KEY["classifier"])

    assert (limits["cpus"], limits["memory"]) == ("4", "4G")
    assert built.log_level == "WARNING"
    assert built.sandbox_enabled is False and built.sandbox.enabled is False
    rates = built.rate_limits
    assert (
        rates.per_tenant is not None and rates.per_user is not None and rates.per_agent is not None
    )
    assert min(r.capacity for r in (rates.per_tenant, rates.per_user, rates.per_agent)) == 1_000_000
    assert (
        min(r.refill_per_s for r in (rates.per_tenant, rates.per_user, rates.per_agent))
        == 1_000_000
    )


def test_the_info_each_gateway_target_must_give_names_the_profile_the_scanner_and_the_model() -> (
    None
):
    assert BY_KEY["passthrough"].info == {
        "profile": "passthrough",
        "scanner": "off",
        "classifier": "none",
    }
    assert BY_KEY["rules-only"].info == {"profile": "full", "scanner": "on", "classifier": "none"}
    assert BY_KEY["classifier"].info is not None
    assert BY_KEY["classifier"].info["classifier"] == "protectai-deberta-v2"


def test_restarting_a_target_drops_the_settings_of_the_last_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, Any]] = []

    def fake_run(args: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        seen.append({"args": args, "env": options["env"]})
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(matrix.subprocess, "run", fake_run)
    monkeypatch.setattr(matrix, "wait_for_gateway", lambda target: {"profile": "full"})
    monkeypatch.setenv("PERF_PROFILE", "passthrough")  # left over from the last target

    configure(BY_KEY["rules-only"])

    [call] = seen
    assert "--force-recreate" in call["args"] and call["args"][-1] == "keystone"
    assert "deploy/perf.override.yml" in call["args"]
    assert "PERF_PROFILE" not in call["env"]
    assert call["env"]["PERF_CLASSIFIER"] == "none"


def test_the_idle_share_is_read_from_the_last_sample_of_top() -> None:
    text = (
        "Processes: 500 total\n"
        "CPU usage: 7.26% user, 12.17% sys, 80.56% idle \n"
        "PhysMem: 15G used\n"
        "CPU usage: 2.23% user, 4.47% sys, 93.29% idle \n"
    )

    assert parse_top_idle(text) == 93.29
    assert parse_top_idle("nothing here") is None


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("123.45% 837.1MiB / 4GiB", (123.45, 837.1)),
        ("0.5% 1.5GiB / 4GiB", (0.5, 1536.0)),
        ("12% 2048KiB / 4GiB", (12.0, 2.0)),
        ("--", None),
        ("", None),
    ],
)
def test_a_line_of_docker_stats_is_read(line: str, expected: tuple[float, float] | None) -> None:
    assert parse_stats(line) == expected


def test_the_samples_of_a_container_are_summarized() -> None:
    sampler = Sampler("c")
    sampler.samples = [(100.0, 800.0), (300.0, 900.0), (200.0, 850.0)]

    assert sampler.summary() == {
        "samples": 3,
        "cpu_percent_mean": 200.0,
        "cpu_percent_max": 300.0,
        "memory_mib_max": 900.0,
    }
    assert Sampler("c").summary() == {"samples": 0}


def test_the_matrix_waits_for_a_quiet_host_and_says_when_it_never_came(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readings = iter([40.0, 60.0, 90.0])
    monkeypatch.setattr(matrix, "idle_percent", lambda: next(readings))
    monkeypatch.setattr(matrix.time, "sleep", lambda _s: None)

    quiet = wait_until_quiet(max_wait_s=60)

    assert quiet["quiet"] is True and quiet["idle_percent"] == 90.0

    monkeypatch.setattr(matrix, "idle_percent", lambda: 30.0)
    ticks = iter(range(0, 10_000, 100))
    monkeypatch.setattr(matrix.time, "monotonic", lambda: float(next(ticks)))
    busy = wait_until_quiet(max_wait_s=250)
    assert busy["quiet"] is False and busy["idle_percent"] == 30.0
    # A host that cannot say how idle it is is not held up.
    monkeypatch.setattr(matrix, "idle_percent", lambda: None)
    assert wait_until_quiet(max_wait_s=1)["quiet"] is True


def fake_measure(**more: Any) -> Any:
    async def measure(
        target: Target, size: int, sessions: int, calls: int, processes: int, sample: bool = True
    ) -> dict[str, Any]:
        if more.get("fail_at") == (target.key, size, sessions):
            raise TimeoutError("a load process did not answer")
        return {
            "size": size,
            "sessions": sessions,
            "calls_each": calls,
            "summary": {
                "p50_ms": 1.0,
                "p95_ms": 2.0,
                "p99_ms": 3.0,
                "throughput": 9.0,
                "errors": 0,
            },
            "errors": {},
            "stopped_early": False,
        }

    return measure


def stub_the_stack(monkeypatch: pytest.MonkeyPatch, **more: Any) -> None:
    monkeypatch.setattr(matrix, "measure", fake_measure(**more))
    monkeypatch.setattr(matrix, "configure", lambda target: {"profile": "full"})
    monkeypatch.setattr(matrix, "machine_facts", lambda: {"cpu": "x"})
    monkeypatch.setattr(matrix, "token_count", lambda size: size // 5)
    monkeypatch.setattr(matrix, "limits", lambda: {"cpus": 4.0, "memory_bytes": 4})


async def test_the_matrix_writes_what_it_has_after_every_run_and_says_when_it_is_whole(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_the_stack(monkeypatch)
    written: list[dict[str, Any]] = []

    def checkpoint(document: dict[str, Any]) -> None:
        written.append(
            {
                "complete": document["complete"],
                "runs": sum(len(e["runs"]) for e in document["targets"].values()),
                "sequential": sum(len(e["sequential"]) for e in document["targets"].values()),
            }
        )

    document = await matrix.matrix(
        [BY_KEY["direct"], BY_KEY["scanner-off"]], [1024, 8192], 200, 20, 200, 4,
        quiet=False, checkpoint=checkpoint,
    )  # fmt: skip

    # Four runs of 200 sessions and four of one session, one write after each, then the last.
    assert len(written) == 9
    assert all(w["complete"] is False for w in written[:-1]) and written[-1]["complete"] is True
    # The run with one session comes first for each payload, then the one with many.
    assert (written[0]["runs"], written[0]["sequential"]) == (0, 1)
    assert (written[1]["runs"], written[1]["sequential"]) == (1, 1)
    assert document["complete"] is True and "error" not in document
    assert document["settings"]["payload_tokens"] == {"1024": 204, "8192": 1638}
    assert document["settings"]["container"] == {"cpus": 4.0, "memory_bytes": 4}


async def test_a_matrix_that_dies_leaves_the_file_with_what_it_measured_and_why_it_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_the_stack(monkeypatch, fail_at=("scanner-off", 8192, 200))
    saved: list[dict[str, Any]] = []

    with pytest.raises(TimeoutError):
        await matrix.matrix(
            [BY_KEY["direct"], BY_KEY["scanner-off"]], [1024, 8192], 200, 20, 0, 4,
            quiet=False, checkpoint=lambda d: saved.append(json.loads(json.dumps(d))),
        )  # fmt: skip

    last = saved[-1]
    assert last["complete"] is False
    assert last["error"] == "TimeoutError: a load process did not answer"
    assert len(last["targets"]["direct"]["runs"]) == 2
    assert len(last["targets"]["scanner-off"]["runs"]) == 1  # the 1 KB run is kept


def test_a_run_is_shown_on_one_line_as_soon_as_it_is_made(
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_ = {
        "size": 1024,
        "sessions": 200,
        "calls_each": 20,
        "summary": {
            "p50_ms": 12.5,
            "p95_ms": 30.0,
            "p99_ms": 41.25,
            "throughput": 99.5,
            "errors": 0,
        },
        "errors": {},
        "stopped_early": True,
    }

    matrix.show("scanner-off", run_)
    matrix.show("rules-only", {**run_, "summary": None, "errors": {"open: ConnectError": 200}})

    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("scanner-off") and "p50     12.5" in out[0]
    assert "99.5/s  errors 0  (stopped early)" in out[0]
    assert "no call was timed: {'open: ConnectError': 200}" in out[1]


def test_the_events_a_gateway_logged_at_warning_or_above_are_counted() -> None:
    lines = "\n".join(
        [
            "INFO:     Uvicorn running on http://0.0.0.0:8080",
            json.dumps({"event": "session_store_failed", "level": "error", "error": "Timeout"}),
            json.dumps({"event": "session_store_failed", "level": "error"}),
            json.dumps({"event": "upstream_call_failed", "level": "warning"}),
            json.dumps({"event": "startup_sync", "level": "info"}),
            json.dumps({"event": "audit_flush_failed", "level": "critical"}),
            json.dumps(["not", "an", "object"]),
            "",
        ]
    )

    counts = matrix.count_log_events(lines)

    # An event that names its error is counted with it, so that the cause is in the count.
    assert counts == {
        "audit_flush_failed": 1,
        "session_store_failed": 1,
        "session_store_failed (Timeout)": 1,
        "upstream_call_failed": 1,
    }
    repeated = "\n".join([json.dumps({"event": "a", "level": "error"})] * 3 + [lines])
    assert next(iter(matrix.count_log_events(repeated))) == "a"  # the commonest first
    assert matrix.count_log_events("") == {}
