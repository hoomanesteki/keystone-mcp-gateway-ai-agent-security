from collections.abc import Mapping, Sequence
from typing import Any

import anyio
import pytest
from anyio.abc import TaskGroup

from keystone.core.errors import Code, Reject
from keystone.core.types import ToolResult
from keystone.db.models import Upstream
from keystone.gateway.dispatch import UpstreamDispatcher
from keystone.gateway.health import UpstreamHealth
from keystone.gateway.upstreams import UpstreamPool, UpstreamTool
from keystone.settings import HealthSettings
from tests.fixtures.calls import make_ctx, make_tool


class Probe:
    """An upstream client whose health a test sets."""

    def __init__(self) -> None:
        self.answer: bool | BaseException = True
        self.hang = False
        self.probes = 0
        self.calls = 0

    async def list_tools(self) -> list[UpstreamTool]:
        return []

    async def call_tool(
        self,
        name: str,
        args: dict[str, Any],
        timeout_s: float,
        meta: Mapping[str, str] | None = None,
    ) -> ToolResult:
        self.calls += 1
        return ToolResult(content=[])

    async def health(self) -> bool:
        self.probes += 1
        if self.hang:
            await anyio.sleep_forever()
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer

    async def aclose(self) -> None:
        return None


class Store:
    def __init__(self, *ids: str) -> None:
        self.rows = {
            i: Upstream(id=i, tenant_id="acme", transport="http", status="unknown") for i in ids
        }
        self.stored: dict[str, str] = {}

    async def list(
        self, tenant_id: str | None = None, *, include_disabled: bool = True
    ) -> Sequence[Upstream]:
        return list(self.rows.values())

    async def set_status_unless_disabled(self, upstream_id: str, status: str) -> bool:
        self.stored[upstream_id] = status
        return True


class Fleet:
    def __init__(self, *ids: str) -> None:
        self.probes = {i: Probe() for i in ids}

    def __call__(self, upstream_id: str, headers: dict[str, str], group: TaskGroup) -> Probe:
        return self.probes[upstream_id]


async def nothing(rows: Sequence[Upstream]) -> None:
    return None


def monitor(pool: UpstreamPool, store: Store, **options: Any) -> UpstreamHealth:
    return UpstreamHealth(pool, store, nothing, **options)  # type: ignore[arg-type]


@pytest.mark.phase(2)
async def test_one_failure_degrades_three_take_it_down_and_one_success_restores_it() -> None:
    async with UpstreamPool(Fleet("bank")) as pool:
        health = monitor(pool, Store("bank"))

        seen = [health.record("bank", ok) for ok in (True, False, False, False, False, True)]

    assert seen == ["up", "degraded", "degraded", "down", "down", "up"]


@pytest.mark.phase(2)
async def test_the_thresholds_are_settings() -> None:
    async with UpstreamPool(Fleet("bank")) as pool:
        health = monitor(pool, Store("bank"), degraded_after=2, down_after=4)

        seen = [health.record("bank", ok) for ok in (False, False, False, False)]

    assert seen == ["up", "degraded", "degraded", "down"]


@pytest.mark.phase(2)
def test_down_after_cannot_come_before_degraded_after() -> None:
    with pytest.raises(ValueError, match="down_after"):
        HealthSettings(degraded_after=3, down_after=2)
    assert HealthSettings().model_dump() == {
        "interval_s": 30.0,
        "timeout_s": 3.0,
        "degraded_after": 1,
        "down_after": 3,
    }


@pytest.mark.phase(2)
async def test_status_is_unknown_before_the_first_probe_and_never_down() -> None:
    async with UpstreamPool(Fleet("bank")) as pool:
        health = monitor(pool, Store("bank"))

        assert health.status("bank") is None
        assert health.is_down("bank") is False
        assert health.is_down("ghost") is False


@pytest.mark.phase(2)
async def test_a_round_probes_each_upstream_on_its_own_and_stores_the_status() -> None:
    fleet = Fleet("bank", "mail")
    store = Store("bank", "mail")
    async with UpstreamPool(fleet) as pool:
        health = monitor(pool, store)
        fleet.probes["bank"].answer = False

        first = await health.check_all()
        second = await health.check_all()
        third = await health.check_all()

    assert first == {"bank": "degraded", "mail": "up"}
    assert second == {"bank": "degraded", "mail": "up"}
    assert third == {"bank": "down", "mail": "up"}
    assert store.stored == {"bank": "down", "mail": "up"}
    assert health.is_down("bank") and not health.is_down("mail")


@pytest.mark.phase(2)
@pytest.mark.parametrize("failure", ["hang", "raise", "false"])
async def test_a_probe_that_hangs_raises_or_says_no_counts_as_a_failure(failure: str) -> None:
    fleet = Fleet("bank")
    probe = fleet.probes["bank"]
    if failure == "hang":
        probe.hang = True
    elif failure == "raise":
        probe.answer = RuntimeError("boom")
    else:
        probe.answer = False
    async with UpstreamPool(fleet) as pool:
        health = monitor(pool, Store("bank"), timeout_s=0.1)

        result = await health.check_all()

    assert result == {"bank": "degraded"}


@pytest.mark.phase(2)
async def test_an_upstream_the_factory_does_not_know_is_unhealthy_not_a_crash() -> None:
    async with UpstreamPool(Fleet()) as pool:
        health = monitor(pool, Store("bank"))

        assert await health.check_all() == {"bank": "degraded"}


@pytest.mark.phase(2)
async def test_an_upstream_that_leaves_is_forgotten_and_one_that_returns_starts_clean() -> None:
    fleet = Fleet("bank")
    store = Store("bank")
    fleet.probes["bank"].answer = False
    async with UpstreamPool(fleet) as pool:
        health = monitor(pool, store)
        for _ in range(3):
            await health.check_all()
        assert health.is_down("bank")

        store.rows.clear()
        await health.check_all()
        assert health.status("bank") is None

        store.rows["bank"] = Upstream(id="bank", tenant_id="acme", transport="http", status="up")
        assert await health.check_all() == {"bank": "degraded"}


@pytest.mark.phase(2)
async def test_a_failing_store_or_directory_does_not_stop_the_probes() -> None:
    fleet = Fleet("bank")
    store = Store("bank")

    async def broken(status: str) -> bool:
        raise ConnectionResetError

    async with UpstreamPool(fleet) as pool:
        health = monitor(pool, store)
        store.set_status_unless_disabled = broken  # type: ignore[method-assign,assignment]

        assert await health.check_all() == {"bank": "up"}
        assert fleet.probes["bank"].probes == 1


@pytest.mark.phase(2)
async def test_run_probes_at_once_and_then_every_interval() -> None:
    fleet = Fleet("bank")
    async with UpstreamPool(fleet) as pool, anyio.create_task_group() as group:
        health = monitor(pool, Store("bank"), interval_s=0.05)
        group.start_soon(health.run)
        with anyio.fail_after(5):
            while fleet.probes["bank"].probes < 3:  # noqa: ASYNC110
                await anyio.sleep(0.02)
        group.cancel_scope.cancel()


@pytest.mark.phase(2)
async def test_a_call_to_a_down_upstream_is_refused_without_touching_it() -> None:
    fleet = Fleet("bank", "mail")
    fleet.probes["bank"].answer = False
    async with UpstreamPool(fleet) as pool:
        health = monitor(pool, Store("bank", "mail"))
        for _ in range(3):
            await health.check_all()
        dispatcher = UpstreamDispatcher(pool, health)
        down = make_ctx(tool=make_tool("bank", "get_balance"))
        down.dispatched = True
        up = make_ctx(tool=make_tool("mail", "list"))

        with pytest.raises(Reject) as raised:
            await dispatcher.dispatch(down)
        await dispatcher.dispatch(up)

    assert raised.value.code is Code.UPSTREAM_ERROR
    assert raised.value.message == "upstream bank is down"
    assert down.dispatched is False
    assert fleet.probes["bank"].calls == 0
    assert fleet.probes["mail"].calls == 1


@pytest.mark.phase(2)
async def test_without_a_monitor_every_call_goes_through() -> None:
    fleet = Fleet("bank")
    async with UpstreamPool(fleet) as pool:
        await UpstreamDispatcher(pool).dispatch(make_ctx(tool=make_tool("bank", "get_balance")))

    assert fleet.probes["bank"].calls == 1
