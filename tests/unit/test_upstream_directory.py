from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import anyio
import pytest
from anyio.abc import TaskGroup

from keystone.core.errors import Code, Reject
from keystone.core.types import ToolResult
from keystone.gateway.upstreams import (
    HttpUpstreamClient,
    UpstreamDirectory,
    UpstreamPool,
    UpstreamTarget,
    UpstreamTool,
    directory_client_factory,
)


class Client:
    def __init__(self) -> None:
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


def http(url: str) -> UpstreamTarget:
    return UpstreamTarget(transport="http", url=url)


@pytest.mark.phase(2)
def test_the_directory_reports_which_targets_are_new_or_different() -> None:
    directory = UpstreamDirectory()

    first = directory.update({"mail": http("http://a/mcp"), "bank": http("http://b/mcp")})
    same = directory.update({"mail": http("http://a/mcp")})
    moved = directory.update({"mail": http("http://c/mcp")})

    assert (sorted(first), same, moved) == (["bank", "mail"], [], ["mail"])
    assert directory.get("mail") == http("http://c/mcp")
    assert directory.get("ghost") is None


@pytest.mark.phase(2)
async def test_the_factory_builds_an_http_client_from_the_directory() -> None:
    directory = UpstreamDirectory()
    directory.update({"mail": http("http://mail.test/mcp")})
    factory = directory_client_factory(directory)

    async with anyio.create_task_group() as group:
        client = factory("mail", {"X-Api-Key": "k"}, group)
        assert isinstance(client, HttpUpstreamClient)
        assert client.url == "http://mail.test/mcp"
        group.cancel_scope.cancel()


@pytest.mark.phase(2)
async def test_the_factory_refuses_an_unknown_upstream_and_an_unserved_transport() -> None:
    directory = UpstreamDirectory()
    directory.update({"sandbox": UpstreamTarget(transport="container_stdio")})
    factory = directory_client_factory(directory)

    async with anyio.create_task_group() as group:
        with pytest.raises(ValueError, match="unknown upstream 'ghost'"):
            factory("ghost", {}, group)
        with pytest.raises(ValueError, match="not served"):
            factory("sandbox", {}, group)
        group.cancel_scope.cancel()


@pytest.mark.phase(2)
async def test_forget_closes_an_idle_client_and_the_next_call_gets_a_new_one() -> None:
    made: list[Client] = []

    def factory(upstream_id: str, headers: dict[str, str], group: TaskGroup) -> Client:
        made.append(Client())
        return made[-1]

    async with UpstreamPool(factory) as pool:
        first = await pool.get("mail", None)
        other = await pool.get("bank", None)

        await pool.forget("mail")
        again = await pool.get("mail", None)

    assert first is not again
    assert [c.closed for c in made] == [
        1,
        1,
        1,
    ]  # first at forget; bank and again when the pool exits
    assert other is made[1]


@pytest.mark.phase(2)
async def test_forget_lets_a_running_call_finish_before_closing() -> None:
    made: list[Client] = []

    def factory(upstream_id: str, headers: dict[str, str], group: TaskGroup) -> Client:
        made.append(Client())
        return made[-1]

    async with UpstreamPool(factory) as pool:
        async with pool.lease("mail", None):
            await pool.forget("mail")
            assert made[0].closed == 0
        assert made[0].closed == 1


@pytest.mark.phase(2)
async def test_a_list_that_never_ends_is_an_error_and_not_a_short_list() -> None:
    page = SimpleNamespace(
        tools=[SimpleNamespace(name="t", description="d", input_schema={})], next_cursor="more"
    )

    class Endless:
        async def list_tools(self, *, cursor: str | None = None, cache_mode: str = "") -> Any:
            return page

    client = HttpUpstreamClient("http://x/mcp", {}, None, upstream_id="mail")  # type: ignore[arg-type]
    with pytest.raises(Reject) as raised:
        await client._list_all(Endless())  # type: ignore[arg-type]

    assert raised.value.code is Code.UPSTREAM_ERROR
    assert "more tools" in raised.value.message


@pytest.mark.phase(2)
async def test_a_reject_raised_inside_a_session_call_is_not_rewritten() -> None:
    client = HttpUpstreamClient("http://x/mcp", {}, None, upstream_id="mail")  # type: ignore[arg-type]

    async def current(attempts: int | None = None) -> Any:
        return object()

    async def action(_: Any) -> None:
        raise Reject(Code.UPSTREAM_ERROR, "too many tools")

    client._client = current  # type: ignore[method-assign]
    with pytest.raises(Reject, match="too many tools"):
        await client._with_session(action)
