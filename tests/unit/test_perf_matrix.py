"""KS-903: the parts of the performance matrix that need no stack.

Nothing here starts a container. The override file is read as the data it is, its variables are fed
to `Settings` the way compose would hand them to Keystone, and the commands the matrix would run
are captured and looked at.
"""

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
