from collections.abc import Mapping
from typing import Any

import anyio
import anyio.lowlevel
import pytest
from anyio.abc import TaskGroup
from pydantic import SecretStr

from keystone.core.types import ToolResult
from keystone.gateway.upstreams import UpstreamPool, UpstreamTool, headers_fingerprint


class FakeClient:
    def __init__(self, upstream_id: str, headers: dict[str, str]) -> None:
        self.upstream_id = upstream_id
        self.headers = headers
        self.closed = 0

    async def list_tools(self) -> list[UpstreamTool]:
        return []

    async def call_tool(
        self,
        name: str,
        args: dict[str, Any],
        timeout_s: float,
        meta: Mapping[str, str] | None = None,
    ) -> ToolResult:
        return ToolResult(content=[])

    async def health(self) -> bool:
        return True

    async def aclose(self) -> None:
        self.closed += 1


class Factory:
    def __init__(self) -> None:
        self.created: list[FakeClient] = []

    def __call__(
        self, upstream_id: str, headers: dict[str, str], task_group: TaskGroup
    ) -> FakeClient:
        client = FakeClient(upstream_id, headers)
        self.created.append(client)
        return client


def secret(**headers: str) -> dict[str, SecretStr]:
    return {name.replace("_", "-"): SecretStr(value) for name, value in headers.items()}


@pytest.mark.phase(1)
async def test_pool_reuses_client_for_same_headers() -> None:
    factory = Factory()

    async with UpstreamPool(factory) as pool:
        first = await pool.get("mail", secret(X_Api_Key="k1"))
        again = await pool.get("mail", secret(X_Api_Key="k1"))
        other_key = await pool.get("mail", secret(X_Api_Key="k2"))
        other_upstream = await pool.get("bank", secret(X_Api_Key="k1"))

    assert first is again
    assert other_key is not first
    assert other_upstream is not first
    assert len(factory.created) == 3


@pytest.mark.phase(1)
async def test_header_names_are_case_insensitive_and_order_does_not_matter() -> None:
    factory = Factory()

    async with UpstreamPool(factory) as pool:
        a = await pool.get("mail", {"X-Api-Key": SecretStr("k"), "X-Tenant": SecretStr("acme")})
        b = await pool.get("mail", {"x-tenant": SecretStr("acme"), "x-api-key": SecretStr("k")})

    assert a is b
    assert len(factory.created) == 1


@pytest.mark.phase(1)
async def test_the_factory_gets_the_real_header_values() -> None:
    factory = Factory()

    async with UpstreamPool(factory) as pool:
        await pool.get("mail", secret(X_Api_Key="s3cret"))
        await pool.get("mail", None)

    assert factory.created[0].headers == {"X-Api-Key": "s3cret"}
    assert factory.created[1].headers == {}


@pytest.mark.phase(1)
async def test_fingerprint_hides_the_values() -> None:
    fingerprint = headers_fingerprint(secret(X_Api_Key="s3cret"))

    assert len(fingerprint) == 64
    assert "s3cret" not in fingerprint
    assert headers_fingerprint({}) != fingerprint


@pytest.mark.phase(1)
async def test_least_recently_used_client_is_evicted_and_closed() -> None:
    factory = Factory()

    async with UpstreamPool(factory, max_clients=2) as pool:
        a = await pool.get("a1", None)
        b = await pool.get("b1", None)
        await pool.get("a1", None)  # a1 is now the most recent
        await pool.get("c1", None)  # evicts b1
        assert [c.closed for c in factory.created] == [0, 1, 0]
        assert await pool.get("a1", None) is a
        assert await pool.get("b1", None) is not b  # b1 comes back as a new client

    assert len(factory.created) == 4


@pytest.mark.phase(2)
async def test_an_evicted_client_closes_after_its_last_in_flight_call() -> None:
    factory = Factory()
    holding = anyio.Event()
    release = anyio.Event()

    async def hold(pool: UpstreamPool) -> None:
        async with pool.lease("a1", None):
            holding.set()
            await release.wait()

    async with UpstreamPool(factory, max_clients=1) as pool, anyio.create_task_group() as tasks:
        tasks.start_soon(hold, pool)
        await holding.wait()
        busy = factory.created[0]

        async with pool.lease("b1", None):  # evicts a1 while a call is running on it
            assert busy.closed == 0
            # A new call for the same upstream never gets the evicted client.
            async with pool.lease("a1", None) as replacement:
                assert replacement is not busy
            assert busy.closed == 0

        release.set()
        await anyio.lowlevel.checkpoint()

    assert busy.closed == 1
    assert [c.closed for c in factory.created] == [1, 1, 1]


@pytest.mark.phase(2)
async def test_an_evicted_client_with_two_calls_closes_after_the_second() -> None:
    factory = Factory()
    first_done = anyio.Event()
    second_done = anyio.Event()
    holding = anyio.Event()

    async def call(pool: UpstreamPool, done: anyio.Event) -> None:
        async with pool.lease("a1", None):
            holding.set()
            await done.wait()

    async with UpstreamPool(factory, max_clients=1) as pool, anyio.create_task_group() as tasks:
        tasks.start_soon(call, pool, first_done)
        await holding.wait()
        tasks.start_soon(call, pool, second_done)
        await anyio.sleep(0.01)
        busy = factory.created[0]
        assert len(factory.created) == 1  # both calls share the one client

        await pool.get("b1", None)  # evicts a1
        assert busy.closed == 0
        first_done.set()
        await anyio.sleep(0.01)
        assert busy.closed == 0  # the second call is still running
        second_done.set()
        await anyio.sleep(0.01)
        assert busy.closed == 1


@pytest.mark.phase(2)
async def test_a_call_that_fails_still_lets_the_evicted_client_close() -> None:
    factory = Factory()

    async with UpstreamPool(factory, max_clients=1) as pool:
        with pytest.raises(RuntimeError, match="call failed"):
            async with pool.lease("a1", None):
                await pool.get("b1", None)
                assert factory.created[0].closed == 0
                raise RuntimeError("call failed")

        assert factory.created[0].closed == 1


@pytest.mark.phase(2)
async def test_a_cancelled_call_still_lets_the_evicted_client_close() -> None:
    factory = Factory()

    async with UpstreamPool(factory, max_clients=1) as pool:
        with anyio.move_on_after(0.05):
            async with pool.lease("a1", None):
                await pool.get("b1", None)
                await anyio.sleep(5)

        assert factory.created[0].closed == 1


@pytest.mark.phase(2)
async def test_every_client_is_closed_once_across_eviction_and_shutdown() -> None:
    factory = Factory()

    async with UpstreamPool(factory, max_clients=1) as pool:
        async with pool.lease("a1", None):
            await pool.get("b1", None)  # evicts a1, which is still leased
        await pool.get("c1", None)  # evicts b1

    assert [c.closed for c in factory.created] == [1, 1, 1]


@pytest.mark.phase(2)
async def test_shutdown_closes_a_leased_client_and_a_late_release_does_not_close_it_again() -> None:
    factory = Factory()
    lease = None

    async with UpstreamPool(factory, max_clients=1) as pool:
        lease = pool.lease("a1", None)
        await lease.__aenter__()
        await pool.get("b1", None)  # evicts a1 while it is leased
        assert factory.created[0].closed == 0

    assert factory.created[0].closed == 1
    await lease.__aexit__(None, None, None)
    assert factory.created[0].closed == 1


@pytest.mark.phase(1)
async def test_leaving_the_pool_closes_every_client_once() -> None:
    factory = Factory()

    async with UpstreamPool(factory) as pool:
        await pool.get("a1", None)
        await pool.get("b1", None)

    assert [c.closed for c in factory.created] == [1, 1]


@pytest.mark.phase(1)
async def test_a_client_that_fails_to_close_does_not_stop_the_others() -> None:
    factory = Factory()

    async with UpstreamPool(factory) as pool:
        broken = await pool.get("a1", None)
        await pool.get("b1", None)

        async def explode() -> None:
            raise RuntimeError("close failed")

        broken.aclose = explode  # type: ignore[method-assign]

    assert [c.closed for c in factory.created] == [0, 1]


@pytest.mark.phase(1)
async def test_get_outside_the_pool_context_is_an_error() -> None:
    pool = UpstreamPool(Factory())

    with pytest.raises(RuntimeError, match="not running"):
        await pool.get("mail", None)


@pytest.mark.phase(1)
async def test_concurrent_gets_share_one_client() -> None:
    factory = Factory()

    async with UpstreamPool(factory) as pool, anyio.create_task_group() as tasks:
        for _ in range(20):
            tasks.start_soon(pool.get, "mail", secret(X_Api_Key="k"))

    assert len(factory.created) == 1
