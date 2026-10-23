"""A registry on the test database, with upstreams that are fakes or the real demo servers.

`running_registry` is a context manager and not a fixture because the upstream pool owns a task
group, which must be entered and left in one task (engineering note 1). A test enters it in its
own body.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import anyio
from anyio.abc import TaskGroup
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.types import ToolResult
from keystone.db.tenants import upsert_tenants
from keystone.gateway.upstreams import (
    ClientFactory,
    UpstreamClient,
    UpstreamDirectory,
    UpstreamPool,
    UpstreamTool,
    directory_client_factory,
)
from keystone.registry.config import ToolOverride
from keystone.registry.repo import ToolRepo, UpstreamRepo, UpstreamSpec
from keystone.registry.service import RegistryService
from keystone.registry.sync import RegistrySyncer
from keystone.settings import TenantConfig

SCHEMA: dict[str, Any] = {"type": "object", "properties": {"id": {"type": "string"}}}


def tool(name: str, description: str | None = None, schema: dict[str, Any] | None = None) -> Any:
    return UpstreamTool(
        name=name,
        description=f"{name} does a thing" if description is None else description,
        input_schema=SCHEMA if schema is None else schema,
    )


class FakeUpstream:
    """An upstream client whose tool list a test edits. Set `error` to make every list fail."""

    def __init__(self, *tools: UpstreamTool) -> None:
        self.tools = list(tools)
        self.error: BaseException | None = None
        self.hang = False
        self.listings = 0
        self.calls: list[str] = []

    async def list_tools(self) -> list[UpstreamTool]:
        self.listings += 1
        if self.hang:
            await anyio.sleep_forever()
        if self.error is not None:
            raise self.error
        return list(self.tools)

    async def call_tool(
        self,
        name: str,
        args: dict[str, Any],
        timeout_s: float,
        meta: Mapping[str, str] | None = None,
    ) -> ToolResult:
        self.calls.append(name)
        return ToolResult(content=[{"type": "text", "text": f"called {name}"}])

    async def health(self) -> bool:
        return self.error is None

    async def aclose(self) -> None:
        return None


def fleet_factory(fleet: Mapping[str, FakeUpstream]) -> ClientFactory:
    def make(upstream_id: str, headers: dict[str, str], group: TaskGroup) -> UpstreamClient:
        return fleet[upstream_id]

    return make


@dataclass
class RegistryEnv:
    service: RegistryService
    syncer: RegistrySyncer
    pool: UpstreamPool
    directory: UpstreamDirectory
    upstreams: UpstreamRepo
    tools: ToolRepo
    fleet: dict[str, FakeUpstream] = field(default_factory=dict)


@asynccontextmanager
async def running_registry(
    sessions: async_sessionmaker[AsyncSession],
    *,
    fleet: Mapping[str, FakeUpstream] | None = None,
    urls: Mapping[str, str] | None = None,
    overrides: Mapping[str, Mapping[str, ToolOverride]] | None = None,
    tenant: str = "acme",
    timeout_s: float = 5.0,
    cache_ttl_s: float = 60.0,
    clock: Callable[[], float] = time.monotonic,
) -> AsyncIterator[RegistryEnv]:
    """Seed the tenant and one upstream row per fake (or per URL), and enter the pool. With
    `fleet` the clients are fakes; with `urls` they are real HTTP clients."""
    await upsert_tenants(sessions, [TenantConfig(id=tenant, name=tenant.title())])
    upstreams = UpstreamRepo(sessions)
    tools = ToolRepo(sessions)
    directory = UpstreamDirectory()
    if fleet is not None:
        factory = fleet_factory(fleet)
        addresses = {name: f"http://{name}.test/mcp" for name in fleet}
    else:
        factory = directory_client_factory(directory)
        addresses = dict(urls or {})
    for name, url in addresses.items():
        await upstreams.upsert(UpstreamSpec(id=name, tenant_id=tenant, url=url))
    pool = UpstreamPool(factory)
    syncer = RegistrySyncer(
        upstreams, tools, pool, directory, overrides=overrides or {}, timeout_s=timeout_s
    )
    service = RegistryService(syncer, cache_ttl_s=cache_ttl_s, clock=clock)
    async with pool:
        yield RegistryEnv(service, syncer, pool, directory, upstreams, tools, dict(fleet or {}))
