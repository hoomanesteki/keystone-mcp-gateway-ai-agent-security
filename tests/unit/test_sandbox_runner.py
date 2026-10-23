"""KS-801 without a daemon: the parts of the runner that are code and not Docker."""

import struct
from typing import Any

import anyio
import pytest

from keystone.sandbox.runner import (
    CALL_LABEL,
    MAX_OUTPUT_BYTES,
    SANDBOX_LABEL,
    OutputCollector,
    SandboxRunner,
    _created_at,
    container_config,
)
from keystone.settings import Settings

pytestmark = pytest.mark.phase(8)


def frame(stream: int, data: bytes) -> bytes:
    return struct.pack(">BxxxL", stream, len(data)) + data


def test_the_collector_keeps_the_two_streams_apart() -> None:
    collector = OutputCollector()

    collector.feed(frame(1, b"out ") + frame(2, b"err ") + frame(1, b"more"))

    assert (collector.stdout, collector.stderr) == (b"out more", b"err ")
    assert collector.truncated is False


@pytest.mark.parametrize("size", [1, 2, 3, 7, 8, 9, 100])
def test_the_collector_reads_the_same_whatever_the_chunks(size: int) -> None:
    stream = frame(1, b"hello ") + frame(2, b"x" * 50) + frame(1, b"") + frame(1, b"world")
    collector = OutputCollector()

    for start in range(0, len(stream), size):
        collector.feed(stream[start : start + size])

    assert (collector.stdout, collector.stderr) == (b"hello world", b"x" * 50)


def test_the_collector_keeps_the_first_bytes_of_each_stream_and_says_it_cut() -> None:
    collector = OutputCollector(limit=10)

    collector.feed(frame(1, b"0123456789") + frame(1, b"abc") + frame(2, b"er"))

    assert (collector.stdout, collector.stderr) == (b"0123456789", b"er")
    assert collector.truncated is True
    # What was dropped is still counted, which is how a flood is seen.
    assert collector.total == 15


def test_output_that_exactly_fills_the_limit_is_not_cut() -> None:
    collector = OutputCollector(limit=10)

    collector.feed(frame(1, b"0123456789"))

    assert collector.truncated is False


def test_the_collector_ignores_streams_it_does_not_know() -> None:
    collector = OutputCollector()

    collector.feed(frame(0, b"echo of stdin") + frame(7, b"?") + frame(1, b"ok"))

    assert (collector.stdout, collector.stderr) == (b"ok", b"")


def test_a_flood_is_seen_when_the_total_passes_the_limit() -> None:
    collector = OutputCollector(limit=4, flood_at=100)

    collector.feed(frame(1, b"x" * 60))
    assert collector.flooded is False
    collector.feed(frame(2, b"y" * 40))

    assert collector.flooded is True


def test_the_default_limit_is_64_kb() -> None:
    assert MAX_OUTPUT_BYTES == 64 * 1024


def test_the_config_holds_every_hardening_flag() -> None:
    config = container_config("img:1", ["python", "-c", "1"], call_id="01ABC")

    assert config["network_mode"] == "none"
    assert config["read_only"] is True
    assert config["tmpfs"] == {"/tmp": "size=64m,noexec", "/workspace": "size=64m"}  # noqa: S108
    assert (config["mem_limit"], config["memswap_limit"]) == ("512m", "512m")
    assert config["nano_cpus"] == 1_000_000_000
    assert config["pids_limit"] == 128
    assert config["cap_drop"] == ["ALL"]
    assert config["security_opt"] == ["no-new-privileges"]
    assert config["user"] == "10001:10001"
    assert config["runtime"] == "runc"
    assert config["labels"] == {SANDBOX_LABEL: "1", CALL_LABEL: "01ABC"}
    assert config["privileged"] is False
    assert config["command"] == ["python", "-c", "1"]
    # No volume of any kind: Keystone runs in a container, and its paths are not the host's.
    assert not {"volumes", "binds", "mounts", "ports", "devices", "cap_add"} & config.keys()


def test_the_runtime_is_the_one_asked_for() -> None:
    config = container_config("img:1", ["true"], runtime="runsc", call_id="x")

    assert config["runtime"] == "runsc"


def test_stdin_is_open_only_when_there_is_input() -> None:
    assert container_config("i", ["c"], call_id="x")["stdin_open"] is False
    assert container_config("i", ["c"], call_id="x", stdin_open=True)["stdin_open"] is True


def test_the_age_of_a_container_is_read_from_both_forms_the_daemon_uses() -> None:
    assert _created_at({"Created": 1_700_000_000}) == 1_700_000_000
    # inspect: nanoseconds and a Z.
    assert _created_at({"Created": "2023-11-14T22:13:20.123456789Z"}) == pytest.approx(
        1_700_000_000.123456
    )
    assert _created_at({"Created": "2023-11-14T22:13:20Z"}) == 1_700_000_000
    assert _created_at({"Created": "yesterday"}) is None
    assert _created_at({}) is None


@pytest.mark.parametrize(
    ("cmd", "timeout_s", "stdin", "message"),
    [
        ([], 5.0, None, "at least a program"),
        (["true"], 0, None, "timeout_s"),
        (["true"], -1, None, "timeout_s"),
        (["true"], 301, None, "timeout_s"),
        (["true"], 5.0, "x" * (1024 * 1024 + 1), "stdin is"),
    ],
)
async def test_arguments_that_make_no_sense_are_refused_before_docker_is_asked(
    cmd: list[str], timeout_s: float, stdin: str | None, message: str
) -> None:
    class NoDocker:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError("Docker was asked")

    runner = SandboxRunner(NoDocker())

    with pytest.raises(ValueError, match=message):
        await runner.run("img:1", cmd, stdin=stdin, timeout_s=timeout_s)


def test_a_runner_needs_no_daemon_to_be_built() -> None:
    runner = SandboxRunner()

    assert runner.runtime == "runc"


def test_a_runner_runs_at_least_one_container_at_a_time() -> None:
    with pytest.raises(ValueError, match="max_concurrent"):
        SandboxRunner(max_concurrent=0)


class FakeContainer:
    def __init__(self, name: str, created: float, *, fails: bool = False) -> None:
        self.attrs = {"Created": created}
        self.short_id = name
        self.fails = fails
        self.removed = False

    def remove(self, **_options: Any) -> None:
        if self.fails:
            raise OSError("the daemon went away")
        self.removed = True


class FakeContainers:
    def __init__(self, found: list[FakeContainer]) -> None:
        self.found = found
        self.filters: list[dict[str, Any]] = []

    def list(self, **options: Any) -> list[FakeContainer]:
        self.filters.append(options)
        return self.found


class FakeClient:
    def __init__(self, found: list[FakeContainer]) -> None:
        self.containers = FakeContainers(found)


async def test_the_reaper_asks_for_the_label_and_keeps_what_is_young() -> None:
    old, young = FakeContainer("old", created=100.0), FakeContainer("young", created=900.0)
    client = FakeClient([old, young])
    runner = SandboxRunner(client, clock=lambda: 1000.0)

    removed = await runner.reap(max_age_s=600)

    assert (removed, old.removed, young.removed) == (1, True, False)
    assert client.containers.filters == [{"all": True, "filters": {"label": "keystone.sandbox=1"}}]


async def test_a_container_that_cannot_be_removed_does_not_stop_the_others() -> None:
    stuck, fine = FakeContainer("stuck", 0.0, fails=True), FakeContainer("fine", 0.0)
    runner = SandboxRunner(FakeClient([stuck, fine]), clock=lambda: 1000.0)

    assert await runner.reap(max_age_s=1) == 1
    assert fine.removed


async def test_the_reaper_goes_on_after_a_failure() -> None:
    client = FakeClient([])
    calls = 0

    def list_containers(**_options: Any) -> list[FakeContainer]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("the daemon is away")
        return []

    client.containers.list = list_containers  # type: ignore[method-assign]
    runner = SandboxRunner(client)

    with anyio.move_on_after(2):
        await runner.run_reaper(interval_s=0.05)

    assert calls >= 3


def test_the_sandbox_is_on_by_default_and_one_variable_turns_it_off(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert Settings().sandbox.enabled is True

    monkeypatch.setenv("KEYSTONE_SANDBOX_ENABLED", "false")

    assert Settings().sandbox.enabled is False


def test_the_nested_spelling_works_and_the_short_one_wins(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KEYSTONE_SANDBOX__ENABLED", "false")
    assert Settings().sandbox.enabled is False

    monkeypatch.setenv("KEYSTONE_SANDBOX_ENABLED", "true")
    assert Settings().sandbox.enabled is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("image", "has space"),
        ("image", ""),
        ("runtime", "Run C"),
        ("timeout_s", 0),
        ("timeout_s", 301),
        ("max_concurrent", 0),
        ("surprise", 1),
    ],
)
def test_bad_sandbox_settings_are_refused(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=field):
        Settings(sandbox={field: value})  # type: ignore[arg-type]
