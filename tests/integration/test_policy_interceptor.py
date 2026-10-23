"""KS-406: the policy decides every call and every tool listing, and says why."""

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import mcp_types as types
import pytest
from mcp import Client
from redis.asyncio import Redis

from keystone.core.types import Risk
from keystone.settings import PolicySettings
from tests.fixtures.approvals import VIRTUAL_TOOLS
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts
from tests.fixtures.policies import copy_pack, reload_policies
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(4), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
TRANSFER = {"from_account": "CHK-001", "to": "SAV-002", "amount": 100}
HIGH_RISK = {"bank__transfer", "mail__send_email"}
CACHE_KEYS = "ks:policy:listcache:*"


async def cache_keys(redis: Redis) -> list[str]:
    return sorted(str(key) for key in await redis.keys(CACHE_KEYS))


async def names(client: Client) -> set[str]:
    return {tool.name for tool in (await client.list_tools()).tools}


def own_app(factory: Factory, tmp_path: Path) -> tuple[KeystoneApp, Path]:
    root = copy_pack(tmp_path)
    return factory(settings={"policy": PolicySettings(root=root, include_demo=True)}), root


async def test_denied_call_returns_reasons(
    keystone_app: KeystoneApp, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    async with mcp_client(keystone_app) as client:  # alice, support
        result = await client.call_tool("bank__transfer", TRANSFER)

    assert result.is_error
    [block] = result.content
    assert isinstance(block, types.TextContent)
    assert re.fullmatch(
        r"\[keystone:KS_DENIED\] call \w+ denied: denied by policy: default-deny", block.text
    )
    # The reasons are in the text, on the block and on the result, for a program to read.
    assert result.meta is not None and block.meta is not None
    assert result.meta["keystone/code"] == "KS_DENIED"
    assert result.meta["keystone/reasons"] == ["default-deny"]
    assert block.meta["keystone/reasons"] == ["default-deny"]
    assert demo_upstreams.state("bank")["calls"] == []
    assert demo_upstreams.state("bank")["transfers"] == []
    [record] = keystone_app.audit.records
    assert (record["effect"], record["reasons"], record["decision_source"]) == (
        "deny",
        ["default-deny"],
        "policy",
    )
    assert (record["outcome"], record["reject_code"], record["dispatched"]) == (
        "rejected",
        "KS_DENIED",
        False,
    )
    assert record["policy_version"] == keystone_app.app.state.policies.version


async def test_an_operator_is_allowed_and_the_audit_names_the_policy(
    keystone_app: KeystoneApp, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    async with mcp_client(keystone_app, user="olivia") as client:
        result = await client.call_tool("bank__transfer", TRANSFER)

    assert not result.is_error
    assert len(demo_upstreams.state("bank")["transfers"]) == 1  # type: ignore[arg-type]
    [record] = keystone_app.audit.records
    assert (record["effect"], record["reasons"], record["decision_source"]) == (
        "allow",
        ["operators-high"],
        "policy",
    )
    assert (record["outcome"], record["dispatched"]) == ("ok", True)


async def test_a_tool_that_is_not_listed_is_still_decided_when_it_is_called(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    async with mcp_client(keystone_app) as client:
        assert "bank__transfer" not in await names(client)
        result = await client.call_tool("bank__transfer", TRANSFER)

    assert result.meta is not None and result.meta["keystone/code"] == "KS_DENIED"


async def test_list_filtered_by_policy(keystone_app: KeystoneApp, mcp_client: McpConnect) -> None:
    async with mcp_client(keystone_app) as alice:
        alices = await names(alice)
    async with mcp_client(keystone_app, user="olivia") as olivia:
        olivias = await names(olivia)

    # Keystone's own two tools are offered to both, whatever the policy says (KS-603).
    assert HIGH_RISK.isdisjoint(alices) and len(alices) == 10 + len(VIRTUAL_TOOLS)
    assert olivias >= HIGH_RISK and len(olivias) == 12 + len(VIRTUAL_TOOLS)
    assert alices >= VIRTUAL_TOOLS and alices < olivias


async def test_list_cache_invalidated_on_reload(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    fake_idp: FakeIdp,
    tmp_path: Path,
    redis: Redis,
) -> None:
    app, root = own_app(keystone_app_factory, tmp_path)
    token = fake_idp.token_for("root")
    base = root / "default" / "access" / "base.cedar"

    async with mcp_client(app, user="olivia") as olivia:
        before = await names(olivia)
        keys_before = await cache_keys(redis)
        assert await names(olivia) == before  # served from the cache, same answer

        text = base.read_text()
        start = text.index('@id("operators-high")')
        end = text.index("@id(", start + 1)
        base.write_text(text[:start] + text[end:])  # remove operators-high
        reloaded = reload_policies(app.base, token)
        after = await names(olivia)  # at once: no wait for the 60 s to pass
        keys_after = await cache_keys(redis)

    assert reloaded.status_code == 200 and reloaded.json()["changed"] is True
    assert before >= HIGH_RISK and HIGH_RISK.isdisjoint(after)
    assert len(before) == 12 + len(VIRTUAL_TOOLS) and len(after) == 10 + len(VIRTUAL_TOOLS)
    # One answer set per policy version: the old one is left to expire, the new one is separate.
    assert len(keys_before) == 1 and len(keys_after) == 2
    versions = {key.rsplit(":", 1)[1] for key in keys_after}
    assert reloaded.json()["version"] in versions and reloaded.json()["previous"] in versions


async def test_a_listing_evaluates_each_tool_once_and_then_uses_the_cache(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    engine = keystone_app.app.state.gateway.tool_filter._engine
    asked: list[str] = []
    real = engine.evaluate

    def spy(principal: Any, action: Any, tool: Any, context: Any) -> Any:
        asked.append(f"{action}:{tool.name}")
        return real(principal, action, tool, context)

    engine.evaluate = spy
    async with mcp_client(keystone_app, user="olivia") as client:
        first = await names(client)
        evaluated = len(asked)
        second = await names(client)

    assert first == second and evaluated == 12
    assert len(asked) == evaluated  # the second listing asked the engine nothing
    assert {entry.split(":")[0] for entry in asked} == {"list_tool"}


async def test_each_caller_has_answers_of_their_own(
    keystone_app: KeystoneApp, mcp_client: McpConnect, redis: Redis
) -> None:
    async with mcp_client(keystone_app) as alice:
        alices = await names(alice)
    async with mcp_client(keystone_app, user="olivia") as olivia:
        olivias = await names(olivia)
    async with mcp_client(keystone_app) as again:
        alices_again = await names(again)

    assert alices_again == alices and alices != olivias
    assert len(await cache_keys(redis)) == 2  # one for alice, one for olivia


async def test_a_new_or_changed_tool_is_decided_without_waiting_for_the_cache(
    keystone_app: KeystoneApp, mcp_client: McpConnect, redis: Redis
) -> None:
    engine = keystone_app.app.state.gateway.tool_filter._engine
    asked: list[str] = []
    real = engine.evaluate

    def spy(principal: Any, action: Any, tool: Any, context: Any) -> Any:
        asked.append(tool.name)
        return real(principal, action, tool, context)

    engine.evaluate = spy
    registry = keystone_app.app.state.registry
    async with mcp_client(keystone_app) as alice:
        await names(alice)
        asked.clear()
        # The registry lists one tool as riskier than before: the cached answer must not be used.
        tools = await registry.list_for_tenant("acme")
        raised = next(t for t in tools if t.name == "files__read_file").model_copy(
            update={"risk": Risk.HIGH}
        )

        async def listing(tenant_id: str) -> list[Any]:
            return [raised if t.name == raised.name else t for t in tools]

        registry.list_for_tenant = listing
        after = await names(alice)

    assert asked == ["files__read_file"]  # only the tool that changed was decided again
    assert "files__read_file" not in after


async def test_a_cache_that_fails_or_lies_does_not_change_the_answer(
    keystone_app: KeystoneApp, mcp_client: McpConnect, redis: Redis
) -> None:
    async with mcp_client(keystone_app) as alice:
        honest = await names(alice)
        [key] = await cache_keys(redis)
        await redis.set(key, "this is not json")  # a damaged entry is replaced, not believed
        damaged = await names(alice)
        await redis.set(key, '{"bank__transfer": ["x", true], "echo__echo": 3}')
        lying = await names(alice)
        await redis.aclose()  # and Redis going away is only a missing cache
        gone = await names(alice)

    assert damaged == honest and lying == honest and gone == honest
    assert "bank__transfer" not in lying


async def test_a_listing_that_cannot_be_decided_shows_nothing(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the filter fell over")

    keystone_app.app.state.gateway.tool_filter.visible = broken
    async with mcp_client(keystone_app, user="olivia") as client:
        listed = await names(client)
        result = await client.call_tool("echo__echo", {"payload": "x"})  # decided on its own

    assert listed == VIRTUAL_TOOLS  # no tool of an upstream, and the two of Keystone's own
    assert not result.is_error and texts(result) == ["x"]
