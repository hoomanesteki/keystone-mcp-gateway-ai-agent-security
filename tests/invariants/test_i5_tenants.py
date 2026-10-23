"""I5: a principal never lists or calls another tenant's tools."""

from collections.abc import Callable

import pytest

from keystone.core.types import ToolRef
from tests.fixtures.approvals import VIRTUAL_TOOLS
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts
from tests.fixtures.upstreams import DemoUpstreams, GlobexFiles

pytestmark = [pytest.mark.phase(3), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
ARGUMENTS: dict[str, dict[str, object]] = {
    "mail__list_emails": {"folder": "inbox"},
    "mail__read_email": {"email_id": "m01"},
    "mail__send_email": {"to": "x@acme.test", "subject": "s", "body": "b"},
    "files__list_files": {"path": "."},
    "files__read_file": {"path": "README.txt"},
    "files__write_file": {"path": "x.txt", "content": "x"},
    "bank__get_balance": {"account": "CHK-001"},
    "bank__list_transactions": {"account": "CHK-001"},
    "bank__transfer": {"from_account": "CHK-001", "to": "SAV-002", "amount": 5},
    "echo__echo": {"payload": "x"},
    "echo__sleep": {"seconds": 0},
    "echo__fail": {"message": "x"},
    "files_globex__list_files": {"path": "."},
    "files_globex__read_file": {"path": "README.txt"},
    "files_globex__write_file": {"path": "x.txt", "content": "x"},
}
ACME = {name for name in ARGUMENTS if not name.startswith("files_globex__")}
GLOBEX = set(ARGUMENTS) - ACME


async def test_i5(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    globex_files: GlobexFiles,
) -> None:
    app = keystone_app_factory(globex=True)
    seen: dict[str, set[str]] = {}
    refused: dict[str, set[str]] = {}

    # Olivia is an operator, so she sees every tool of her tenant (KS-406).
    for user, own, other in (("olivia", ACME, GLOBEX), ("bob", GLOBEX, ACME)):
        async with mcp_client(app, user=user) as client:
            seen[user] = {t.name for t in (await client.list_tools()).tools}
            refused[user] = set()
            for name in sorted(other):
                result = await client.call_tool(name, ARGUMENTS[name])
                assert result.is_error, f"{user} called {name}"
                assert (
                    result.meta is not None and result.meta["keystone/code"] == "KS_TOOL_NOT_FOUND"
                )
                assert (
                    "is not allowed" not in texts(result)[0]
                    and "forbidden" not in texts(result)[0].lower()
                )
                refused[user].add(name)
        assert seen[user] == own | VIRTUAL_TOOLS and seen[user].isdisjoint(other)
        assert refused[user] == other

    # Nothing reached the other tenant's upstreams, and every refusal was audited as such.
    assert all(
        demo_upstreams.state(name)["calls"] == [] for name in ("mail", "files", "bank", "echo")
    )
    assert globex_files.state()["calls"] == []
    records = app.audit.records
    assert len(records) == len(ACME) + len(GLOBEX)
    assert {(r["reject_code"], r["dispatched"]) for r in records} == {("KS_TOOL_NOT_FOUND", False)}
    assert {r["user_id"]: r["tenant_id"] for r in records} == {"olivia": "acme", "bob": "globex"}


class LeakyRegistry:
    """A registry with the bug I5 guards against: it ignores the tenant it is asked for."""

    def __init__(self, inner: object) -> None:
        self.inner = inner

    async def list_for_tenant(self, tenant_id: str) -> list[ToolRef]:
        tools: list[ToolRef] = []
        for tenant in ("acme", "globex"):
            tools += await self.inner.list_for_tenant(tenant)  # type: ignore[attr-defined]
        return tools

    async def get(self, tenant_id: str, name: str) -> ToolRef | None:
        for tenant in ("acme", "globex"):
            found: ToolRef | None = await self.inner.get(tenant, name)  # type: ignore[attr-defined]
            if found is not None:
                return found
        return None


async def test_a_registry_that_forgets_the_tenant_still_does_not_leak(
    keystone_app_factory: Factory, mcp_client: McpConnect, globex_files: GlobexFiles
) -> None:
    app = keystone_app_factory(globex=True)
    gateway = app.app.state.gateway
    gateway.registry = LeakyRegistry(gateway.registry)

    async with mcp_client(app, user="olivia") as olivia:
        listed = {t.name for t in (await olivia.list_tools()).tools}
        called = await olivia.call_tool("files_globex__read_file", {"path": "README.txt"})

    assert listed == ACME | VIRTUAL_TOOLS
    assert called.is_error and called.meta is not None
    assert called.meta["keystone/code"] == "KS_TOOL_NOT_FOUND"
    assert globex_files.state()["calls"] == []
