from collections.abc import Mapping
from typing import Any

import pytest
from anyio.abc import TaskGroup

from keystone.core.canonical import canonical_json, sha256_hex
from keystone.core.errors import Code, Reject
from keystone.core.types import Risk, ToolResult, ToolStatus
from keystone.gateway.upstreams import UpstreamPool, UpstreamTool
from keystone.registry.static import StaticRegistry
from keystone.settings import UpstreamConfig

SCHEMA = {"type": "object", "properties": {"id": {"type": "string"}}}


class Listing:
    def __init__(self, tools: list[UpstreamTool] | Reject) -> None:
        self.tools = tools

    async def list_tools(self) -> list[UpstreamTool]:
        if isinstance(self.tools, Reject):
            raise self.tools
        return self.tools

    async def call_tool(
        self,
        name: str,
        args: dict[str, Any],
        timeout_s: float,
        meta: Mapping[str, str] | None = None,
    ) -> ToolResult:
        raise NotImplementedError

    async def health(self) -> bool:
        return True

    async def aclose(self) -> None:
        return None


def tool(name: str, description: str = "does a thing") -> UpstreamTool:
    return UpstreamTool(name=name, description=description, input_schema=SCHEMA)


def pool_of(listings: dict[str, Listing]) -> UpstreamPool:
    def factory(upstream_id: str, headers: dict[str, str], group: TaskGroup) -> Listing:
        return listings[upstream_id]

    return UpstreamPool(factory)


def config(upstream_id: str, tenant: str = "acme") -> UpstreamConfig:
    return UpstreamConfig(id=upstream_id, tenant=tenant, url=f"http://{upstream_id}/mcp")


@pytest.mark.phase(1)
async def test_tools_are_named_per_upstream_and_hashed() -> None:
    registry = StaticRegistry()
    listings = {
        "mail": Listing([tool("read_email", "Read one email")]),
        "bank": Listing([tool("transfer")]),
    }

    async with pool_of(listings) as pool:
        await registry.load(pool, [config("mail"), config("bank")])

    refs = await registry.list_for_tenant("acme")
    assert [r.name for r in refs] == ["bank__transfer", "mail__read_email"]
    ref = await registry.get("acme", "mail__read_email")
    assert ref is not None
    assert (ref.upstream_id, ref.upstream_tool_name) == ("mail", "read_email")
    assert ref.description_hash == sha256_hex(canonical_json("Read one email"))
    assert ref.schema_hash == sha256_hex(canonical_json(SCHEMA))
    assert (ref.risk, ref.status, ref.tenant_id) == (Risk.MEDIUM, ToolStatus.ACTIVE, "acme")


@pytest.mark.phase(1)
async def test_a_tenant_only_sees_its_own_upstreams() -> None:
    registry = StaticRegistry()
    listings = {"mail": Listing([tool("read_email")]), "files_globex": Listing([tool("read_file")])}

    async with pool_of(listings) as pool:
        await registry.load(pool, [config("mail"), config("files_globex", tenant="globex")])

    assert [r.name for r in await registry.list_for_tenant("acme")] == ["mail__read_email"]
    assert [r.name for r in await registry.list_for_tenant("globex")] == ["files_globex__read_file"]
    assert await registry.get("acme", "files_globex__read_file") is None
    assert await registry.list_for_tenant("initech") == []


@pytest.mark.phase(1)
async def test_an_upstream_that_cannot_answer_is_skipped() -> None:
    registry = StaticRegistry()
    listings = {
        "mail": Listing([tool("read_email")]),
        "bank": Listing(Reject(Code.UPSTREAM_ERROR, "the upstream server is not reachable")),
    }

    async with pool_of(listings) as pool:
        await registry.load(pool, [config("bank"), config("mail")])

    assert [r.name for r in await registry.list_for_tenant("acme")] == ["mail__read_email"]


@pytest.mark.phase(1)
async def test_a_tool_name_that_cannot_be_exposed_is_skipped() -> None:
    registry = StaticRegistry()
    listings = {"mail": Listing([tool("read.email"), tool("read_email"), tool("x" * 70)])}

    async with pool_of(listings) as pool:
        await registry.load(pool, [config("mail")])

    assert [r.name for r in await registry.list_for_tenant("acme")] == ["mail__read_email"]


@pytest.mark.phase(1)
async def test_an_http_upstream_without_a_url_fails_loudly() -> None:
    registry = StaticRegistry()

    async with pool_of({}) as pool:
        with pytest.raises(ValueError, match="needs a tenant and a url"):
            await registry.load(pool, [UpstreamConfig(id="mail")])


@pytest.mark.phase(1)
async def test_builtin_upstreams_are_not_loaded_in_phase_1() -> None:
    registry = StaticRegistry()

    async with pool_of({}) as pool:
        await registry.load(
            pool, [UpstreamConfig(id="sandbox", tenant="acme", transport="builtin")]
        )

    assert await registry.list_for_tenant("acme") == []
