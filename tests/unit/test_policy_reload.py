"""KS-403: a reload swaps the policy set in force whole, or changes nothing."""

import os
import signal
from collections.abc import Callable
from pathlib import Path

import anyio
import pytest

from keystone.policy.store import (
    PolicyLoadError,
    PolicyNotLoaded,
    PolicySet,
    PolicyStore,
    reload_on_sighup,
)
from tests.fixtures.policies import forbid, permit, write_policies

TENANTS = ("acme",)


class Recorder:
    """Stands in for the policy_versions table."""

    def __init__(self) -> None:
        self.versions: list[str] = []
        self.fail = False

    async def record(self, policy_set: PolicySet) -> None:
        if self.fail:
            raise RuntimeError("the database is down")
        self.versions.append(policy_set.version)


async def wait_for(condition: Callable[[], bool], seconds: float = 10.0) -> None:
    deadline = anyio.current_time() + seconds
    while anyio.current_time() < deadline:
        if condition():
            return
        await anyio.sleep(0.02)
    raise AssertionError(f"not true after {seconds:g} s")


def started(tmp_path: Path, recorder: Recorder | None = None) -> tuple[PolicyStore, Path]:
    root = write_policies(
        tmp_path / "policies", {"default/access/base.cedar": permit("base-permit")}
    )
    store = PolicyStore(root, TENANTS, recorder=recorder)
    store.start()
    return store, root / "default" / "access" / "base.cedar"


@pytest.mark.phase(4)
def test_nothing_is_in_force_before_the_first_load(tmp_path: Path) -> None:
    store = PolicyStore(tmp_path, TENANTS)

    with pytest.raises(PolicyNotLoaded):
        _ = store.current


@pytest.mark.phase(4)
def test_the_first_load_of_a_bad_set_raises_because_there_is_nothing_to_keep(
    tmp_path: Path,
) -> None:
    root = write_policies(tmp_path / "policies", {"default/access/base.cedar": "permit ("})
    store = PolicyStore(root, TENANTS)

    with pytest.raises(PolicyLoadError):
        store.start()


@pytest.mark.phase(4)
async def test_a_valid_edit_replaces_the_set_and_is_recorded(tmp_path: Path) -> None:
    recorder = Recorder()
    store, base = started(tmp_path, recorder)
    first = store.version

    unchanged = await store.reload()
    base.write_text(permit("base-permit", "context.hour_utc < 20"))
    edited = await store.reload()

    assert (unchanged.ok, unchanged.changed, unchanged.version) == (True, False, first)
    assert (edited.ok, edited.changed, edited.previous) == (True, True, first)
    assert store.version == edited.version != first
    assert recorder.versions == [unchanged.version, edited.version]


@pytest.mark.phase(4)
async def test_a_refused_edit_changes_nothing_and_says_why(tmp_path: Path) -> None:
    recorder = Recorder()
    store, base = started(tmp_path, recorder)
    before = store.current
    base.write_text("permit (principal, action, resource")

    refused = await store.reload()

    assert not refused.ok and not refused.changed
    assert refused.version == refused.previous == before.version
    assert refused.errors and refused.errors[0].startswith("default/access/base.cedar: ")
    assert store.current is before  # the very same set, not a copy
    assert recorder.versions == []  # a refused set is never recorded


@pytest.mark.phase(4)
async def test_a_set_that_could_not_be_recorded_is_not_put_in_force(tmp_path: Path) -> None:
    recorder = Recorder()
    store, base = started(tmp_path, recorder)
    before = store.current
    base.write_text(forbid("base-permit"))
    recorder.fail = True

    refused = await store.reload()

    assert not refused.ok
    assert refused.errors == ("the new version could not be recorded",)
    assert store.current is before


@pytest.mark.phase(4)
async def test_a_set_that_cannot_be_read_at_all_keeps_the_old_one(tmp_path: Path) -> None:
    store, _ = started(tmp_path)
    before = store.current
    store.root = tmp_path / "gone"

    refused = await store.reload()

    assert not refused.ok and "does not exist" in refused.errors[0]
    assert store.current is before


@pytest.mark.phase(4)
async def test_reloads_run_one_at_a_time(tmp_path: Path) -> None:
    recorder = Recorder()
    store, base = started(tmp_path, recorder)
    base.write_text(permit("base-permit", "context.hour_utc < 20"))
    results = []

    async def reload_once() -> None:
        results.append(await store.reload())

    async with anyio.create_task_group() as group:
        for _ in range(5):
            group.start_soon(reload_once)

    assert all(r.ok for r in results)
    assert sorted(r.changed for r in results) == [False, False, False, False, True]
    assert len(set(recorder.versions)) == 1


@pytest.mark.phase(4)
async def test_sighup_reloads_the_policies(tmp_path: Path) -> None:
    store, base = started(tmp_path)
    first = store.version
    base.write_text(permit("base-permit", "context.hour_utc < 20"))

    async with anyio.create_task_group() as group:
        group.start_soon(reload_on_sighup, store)
        await anyio.sleep(0.1)  # let it install its handler
        os.kill(os.getpid(), signal.SIGHUP)
        await wait_for(lambda: store.version != first)
        group.cancel_scope.cancel()

    assert store.version != first


@pytest.mark.phase(4)
async def test_sighup_with_a_bad_edit_keeps_the_set_in_force(tmp_path: Path) -> None:
    store, base = started(tmp_path)
    before = store.current
    base.write_text("forbid (")

    async with anyio.create_task_group() as group:
        group.start_soon(reload_on_sighup, store)
        await anyio.sleep(0.1)
        os.kill(os.getpid(), signal.SIGHUP)
        await anyio.sleep(0.5)
        group.cancel_scope.cancel()

    assert store.current is before
