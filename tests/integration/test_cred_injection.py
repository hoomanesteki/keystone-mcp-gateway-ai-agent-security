"""KS-306: Keystone adds the upstream credential itself, and the agent never sees it."""

import secrets
import time
from collections.abc import Callable

import anyio
import httpx2
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect
from keystone.gateway.upstreams import AUTH_REFUSED_MESSAGE
from keystone.identity.credential_repo import CredentialRepo
from keystone.identity.vault import Cipher, Vault, key_id
from keystone.registry.config import UpstreamConfig
from keystone.settings import HealthSettings
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import TEST_MASTER_KEY, KeystoneApp, McpConnect
from tests.fixtures.mcp_results import texts
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(3), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]
Factory = Callable[..., KeystoneApp]


class AllowsExceptForbidden:
    """A policy slot that allows every call but one, so the credential slot is reached."""

    name = "policy"

    async def before_call(self, ctx: CallContext) -> None:
        if ctx.arguments.get("payload") == "forbidden":
            raise Reject(Code.DENIED, "not allowed")
        ctx.decision = Decision(effect=Effect.ALLOW, source="policy")

    async def after_call(self, ctx: CallContext) -> None:
        return None


async def test_upstream_receives_header(
    keystone_app_factory: Factory, mcp_client: McpConnect, keyed_upstreams: DemoUpstreams
) -> None:
    app = keystone_app_factory(keyed=True)
    # The startup sync used the credential too. Start counting from here, so that what is
    # checked below is the call and not the sync.
    keyed_upstreams.reset()
    assert keyed_upstreams.state("mail")["api_key_received"] is False

    async with mcp_client(app) as client:
        listed = await client.list_tools()
        read = await client.call_tool("mail__list_emails", {"folder": "inbox"})

    assert len(listed.tools) == 12
    assert not read.is_error
    assert keyed_upstreams.state("mail")["api_key_received"] is True
    assert keyed_upstreams.state("mail")["calls"] == ["list_emails"]
    for untouched in ("files", "bank", "echo"):
        assert keyed_upstreams.state(untouched)["api_key_received"] is False


async def test_agent_never_receives_credential(
    keystone_app_factory: Factory, mcp_client: McpConnect, keyed_upstreams: DemoUpstreams
) -> None:
    app = keystone_app_factory(keyed=True)
    keys = list(keyed_upstreams.keys.values())

    async with mcp_client(app, user="olivia") as client:
        # What the handshake told the agent, and the tool list.
        seen = [
            client.server_capabilities.model_dump_json(by_alias=True),
            str(client.server_info),
            str(client.instructions),
        ]
        seen.append((await client.list_tools()).model_dump_json(by_alias=True))
        for name, arguments in (
            ("mail__list_emails", {"folder": "inbox"}),
            ("bank__get_balance", {"account": "CHK-001"}),
            ("echo__echo", {"payload": "hello"}),
            ("echo__fail", {"message": "on purpose"}),
            ("echo__echo", {"payload": 1}),
            ("echo__missing", {}),
        ):
            seen.append((await client.call_tool(name, arguments)).model_dump_json(by_alias=True))

    everything = "\n".join(seen)
    assert len(seen) == 10 and "email" in everything  # the calls really ran
    for key in keys:
        assert key not in everything


async def test_a_credential_missing_from_the_vault_gives_an_upstream_error(
    keystone_app_factory: Factory, mcp_client: McpConnect, sessionmaker: Sessions
) -> None:
    app = keystone_app_factory(keyed=True)
    async with sessionmaker() as session, session.begin():
        await session.execute(text("DELETE FROM credentials"))

    # No key goes with the call, the upstream answers 401, and the agent gets KS_UPSTREAM_ERROR.
    async with mcp_client(app) as client:
        with anyio.fail_after(30):
            result = await client.call_tool("mail__list_emails", {"folder": "inbox"})

    assert result.is_error
    assert result.meta is not None and result.meta["keystone/code"] == "KS_UPSTREAM_ERROR"
    [record] = app.audit.records
    assert (record["outcome"], record["reject_code"]) == ("error", "KS_UPSTREAM_ERROR")


@pytest.mark.phase(4)
async def test_an_upstream_that_refuses_the_credential_gives_upstream_error_at_once(
    keystone_app_factory: Factory, mcp_client: McpConnect, sessionmaker: Sessions
) -> None:
    # KS-391. Before it, this call waited through the reconnect backoff, about 4 s.
    app = keystone_app_factory(keyed=True)
    async with sessionmaker() as session, session.begin():
        await session.execute(text("DELETE FROM credentials"))

    async with mcp_client(app) as client:
        started = time.monotonic()
        result = await client.call_tool("mail__list_emails", {"folder": "inbox"})
        elapsed = time.monotonic() - started

    assert result.is_error
    assert result.meta is not None and result.meta["keystone/code"] == "KS_UPSTREAM_ERROR"
    assert AUTH_REFUSED_MESSAGE in texts(result)[0]
    assert elapsed < 1.0
    [record] = app.audit.records
    assert (record["outcome"], record["reject_code"]) == ("error", "KS_UPSTREAM_ERROR")


async def test_sync_and_health_probes_use_the_upstreams_own_credential(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    # Every upstream demands its key even for tools/list, so a sync or a probe without the
    # credential would fail: the registry would be empty and the probes would say `degraded`.
    app = keystone_app_factory(
        keyed=True, settings={"health": HealthSettings(interval_s=0.2, timeout_s=2)}
    )
    health = app.app.state.health
    names = ("bank", "echo", "files", "mail")

    deadline = anyio.current_time() + 15
    while anyio.current_time() < deadline:
        if all(health.status(name) is not None for name in names):
            break
        await anyio.sleep(0.1)
    await anyio.sleep(0.8)  # and a few more rounds, so one lucky probe cannot pass for all

    assert {name: health.status(name) for name in names} == dict.fromkeys(names, "up")
    statuses = httpx2.get(f"{app.base}/readyz", timeout=10).json()["upstreams"]
    assert statuses == dict.fromkeys(names, "up")
    async with mcp_client(app) as client:
        assert len((await client.list_tools()).tools) == 12


async def test_credentials_from_the_environment_are_stored_encrypted_and_not_rewritten(
    keystone_app_factory: Factory, sessionmaker: Sessions, keyed_upstreams: DemoUpstreams
) -> None:
    first = keystone_app_factory(keyed=True)
    async with sessionmaker() as session:
        before = (
            await session.execute(
                text("SELECT upstream_id, ciphertext, key_id FROM credentials ORDER BY 1")
            )
        ).all()
    first.thread.stop()

    keystone_app_factory(keyed=True)
    async with sessionmaker() as session:
        after = (
            await session.execute(
                text("SELECT upstream_id, ciphertext, key_id FROM credentials ORDER BY 1")
            )
        ).all()

    assert [row[0] for row in before] == ["bank", "echo", "files", "mail"]
    assert {row[2] for row in before} == {key_id(TEST_MASTER_KEY)}
    for _, ciphertext, _ in before:
        for key in keyed_upstreams.keys.values():
            assert key.encode() not in bytes(ciphertext)
    assert [bytes(r[1]) for r in after] == [bytes(r[1]) for r in before]  # nothing was rewritten


async def test_a_variable_that_is_missing_at_startup_keeps_the_stored_credential(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    keystone_app_factory(keyed=True).thread.stop()  # the credentials are stored now

    app = keystone_app_factory(keyed=True, environ={})  # and the environment no longer has them
    async with mcp_client(app) as client:
        result = await client.call_tool("mail__list_emails", {"folder": "inbox"})

    assert not result.is_error


async def test_per_user_credentials_are_chosen_by_the_caller(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    sessionmaker: Sessions,
    keyed_upstreams: DemoUpstreams,
    fake_idp: FakeIdp,
) -> None:
    echo = UpstreamConfig(
        id="echo",
        tenant="acme",
        url=keyed_upstreams.url("echo"),
        credential_mode="per_user",
        # The service credential, for the sync and the probes. Calls use the user's own.
        credential_env={"X-Api-Key": "ECHO_API_KEY"},
    )
    app = keystone_app_factory(keyed=True, settings={"upstreams": [echo]})
    vault = Vault(Cipher(TEST_MASTER_KEY), CredentialRepo(sessionmaker))
    await vault.set("acme", "echo", {"X-Api-Key": keyed_upstreams.keys["echo"]}, "alice")
    await vault.set("acme", "echo", {"X-Api-Key": f"wrong-{secrets.token_hex(8)}"}, "lena")

    async with mcp_client(app, user="alice") as alice:
        good = await alice.call_tool("echo__echo", {"payload": "as alice"})
    async with mcp_client(app, user="olivia") as olivia:
        nobody = await olivia.call_tool("echo__echo", {"payload": "as olivia"})
    async with mcp_client(app, user="lena", agent="ops-agent") as lena:
        with anyio.fail_after(30):
            wrong = await lena.call_tool("echo__echo", {"payload": "as lena"})

    assert not good.is_error and texts(good) == ["as alice"]
    assert nobody.meta is not None and nobody.meta["keystone/code"] == "KS_DENIED"
    assert "no credential for this user on echo" in texts(nobody)[0]
    assert wrong.meta is not None and wrong.meta["keystone/code"] == "KS_UPSTREAM_ERROR"
    outcomes = [(r["user_id"], r["outcome"]) for r in app.audit.records]
    assert outcomes == [("alice", "ok"), ("olivia", "rejected"), ("lena", "error")]


async def test_a_call_refused_by_policy_never_opens_the_vault(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(keyed=True, interceptors={"policy": AllowsExceptForbidden()})
    vault = app.app.state.vault
    opened: list[str] = []
    real = vault.headers_for

    async def counting(tenant_id: str, upstream_id: str, user_id: str | None) -> object:
        opened.append(upstream_id)
        return await real(tenant_id, upstream_id, user_id)

    vault.headers_for = counting
    async with mcp_client(app) as client:
        refused = await client.call_tool("echo__echo", {"payload": "forbidden"})
        invalid = await client.call_tool("echo__echo", {"payload": 7})
        allowed = await client.call_tool("echo__echo", {"payload": "fine"})

    assert refused.is_error and invalid.is_error and not allowed.is_error
    assert opened == ["echo"]  # only the call that went through opened the vault
