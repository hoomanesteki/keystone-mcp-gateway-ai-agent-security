"""KS-304: /mcp needs a token, and a session belongs to the principal that opened it."""

from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.types import SessionState
from keystone.db.models import McpSession
from keystone.gateway.sessions import session_key
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(3), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]
HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "auth-test", "version": "0"},
    },
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
METADATA_PATH = "/.well-known/oauth-protected-resource"


def request(
    app: KeystoneApp,
    token: str | None,
    body: dict[str, Any] | None,
    *,
    session: str | None = None,
    method: str = "POST",
    headers: dict[str, str] | None = None,
) -> httpx2.Response:
    sent = dict(HEADERS) | (headers or {})
    if token is not None:
        sent["authorization"] = f"Bearer {token}"
    if session is not None:
        sent["mcp-session-id"] = session
    return httpx2.request(method, app.url, json=body, headers=sent, timeout=10)


def open_session(app: KeystoneApp, token: str) -> str:
    """What an MCP client does first: `initialize`, then the `initialized` notification."""
    opened = request(app, token, INITIALIZE)
    assert opened.status_code == 200, opened.text
    session = opened.headers["mcp-session-id"]
    assert request(app, token, INITIALIZED, session=session).status_code == 202
    return session


def tool_count(response: httpx2.Response) -> int:
    assert response.status_code == 200, response.text
    # The reply is one server-sent event or one JSON document, depending on the client's Accept.
    text = response.text
    return text.count('"name"')


@pytest.mark.phase(3)
async def test_no_token_401_with_metadata_header(keystone_app: KeystoneApp) -> None:
    challenge = f'Bearer resource_metadata="{keystone_app.base}{METADATA_PATH}"'

    posted = request(keystone_app, None, INITIALIZE)
    streamed = request(keystone_app, None, None, method="GET")
    ended = request(keystone_app, None, None, method="DELETE", session="whatever")

    for response in (posted, streamed, ended):
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == challenge
    assert posted.json() == {"error": "unauthorized", "reason": "no_credentials"}


@pytest.mark.phase(3)
async def test_metadata_endpoint(keystone_app: KeystoneApp, fake_idp: FakeIdp) -> None:
    response = httpx2.get(f"{keystone_app.base}{METADATA_PATH}", timeout=10)

    assert response.status_code == 200
    assert response.json() == {
        "resource": f"{keystone_app.base}/mcp",
        "authorization_servers": [fake_idp.issuer],
        "bearer_methods_supported": ["header"],
    }


@pytest.mark.phase(3)
async def test_the_public_base_url_names_the_resource_when_it_is_set(
    keystone_app_factory: Callable[..., KeystoneApp], fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory(settings={"public_base_url": "https://keystone.example.test/"})

    metadata = httpx2.get(f"{app.base}{METADATA_PATH}", timeout=10).json()
    refused = request(app, None, INITIALIZE)

    assert metadata["resource"] == "https://keystone.example.test/mcp"
    assert refused.headers["www-authenticate"] == (
        'Bearer resource_metadata="https://keystone.example.test/.well-known/'
        'oauth-protected-resource"'
    )


@pytest.mark.phase(3)
async def test_an_invalid_token_gets_the_same_challenge(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    challenge = f'Bearer resource_metadata="{keystone_app.base}{METADATA_PATH}"'
    cases = {
        "malformed": "not-a-token",
        "expired": fake_idp.make_token("alice", "acme", exp_in=-300),
        "wrong_audience": fake_idp.make_token("alice", "acme", aud="other"),
        "alg_not_allowed": fake_idp.make_token("alice", "acme", alg="none"),
        "missing_tenant": fake_idp.make_token("alice", None),
    }

    for reason, token in cases.items():
        response = request(keystone_app, token, INITIALIZE)
        assert response.status_code == 401, reason
        assert response.headers["www-authenticate"] == challenge
        assert response.json() == {"error": "invalid_token", "reason": reason}


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    "authorization", ["Basic YWxpY2U6c2VjcmV0", "Bearer", "Bearer a b", "Token abc", "Bearer a;b"]
)
async def test_a_header_that_is_not_a_bearer_token_is_refused(
    keystone_app: KeystoneApp, authorization: str
) -> None:
    response = request(keystone_app, None, INITIALIZE, headers={"authorization": authorization})

    assert response.status_code == 401
    assert response.json()["reason"] == "malformed"


@pytest.mark.phase(3)
async def test_a_token_for_an_agent_that_is_not_listed_gets_403(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    token = fake_idp.token_for("alice", agent="rogue-agent")

    response = request(keystone_app, token, INITIALIZE)

    assert response.status_code == 403
    assert response.json() == {"error": "forbidden", "reason": "unknown_agent"}
    assert "www-authenticate" not in response.headers


@pytest.mark.phase(3)
async def test_a_listed_agent_trust_and_an_unlisted_one_that_is_allowed(
    keystone_app_factory: Callable[..., KeystoneApp],
    fake_idp: FakeIdp,
    mcp_client: McpConnect,
) -> None:
    app = keystone_app_factory(settings={"auth": {"mode": "oidc", "allow_unknown_agents": True}})

    async with mcp_client(app, token=fake_idp.token_for("alice", agent="rogue-agent")) as client:
        names = [t.name for t in (await client.list_tools()).tools]

    assert "echo__echo" in names


@pytest.mark.phase(3)
async def test_an_idp_that_cannot_be_reached_gives_503_and_not_401(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    fake_idp.jwks_status = 500

    response = request(keystone_app, fake_idp.token_for("alice"), INITIALIZE)

    assert response.status_code == 503
    assert response.json() == {"error": "temporarily_unavailable", "reason": "keys_unavailable"}
    assert response.headers["retry-after"] == "5"
    assert "www-authenticate" not in response.headers


@pytest.mark.phase(3)
async def test_the_host_check_comes_before_the_token_check(keystone_app: KeystoneApp) -> None:
    response = request(keystone_app, None, INITIALIZE, headers={"host": "evil.example"})

    assert response.status_code == 421


@pytest.mark.phase(3)
async def test_health_and_metadata_need_no_token(keystone_app: KeystoneApp) -> None:
    assert httpx2.get(f"{keystone_app.base}/healthz", timeout=10).status_code == 200
    assert httpx2.get(f"{keystone_app.base}/readyz", timeout=10).status_code == 200
    assert httpx2.get(f"{keystone_app.base}{METADATA_PATH}", timeout=10).status_code == 200


@pytest.mark.phase(3)
async def test_session_bound_to_principal(
    keystone_app_factory: Callable[..., KeystoneApp], fake_idp: FakeIdp
) -> None:
    keystone_app = keystone_app_factory(globex=True)  # bob is a known principal of another tenant
    alice = fake_idp.token_for("alice")
    bob = fake_idp.token_for("bob")
    session = open_session(keystone_app, alice)

    posted = request(keystone_app, bob, LIST_TOOLS, session=session)
    streamed = request(keystone_app, bob, None, session=session, method="GET")
    ended = request(keystone_app, bob, None, session=session, method="DELETE")

    for response in (posted, streamed, ended):
        assert response.status_code == 403
        assert "session belongs to another principal" in response.text
    # The refused attempts changed nothing: the session still works for alice, and bob's own
    # session is a different one.
    assert tool_count(request(keystone_app, alice, LIST_TOOLS, session=session)) > 0
    bobs = open_session(keystone_app, bob)
    assert bobs != session
    assert request(keystone_app, alice, LIST_TOOLS, session=bobs).status_code == 403


@pytest.mark.phase(3)
async def test_token_swap_on_session_rejected(
    keystone_app_factory: Callable[..., KeystoneApp], fake_idp: FakeIdp
) -> None:
    keystone_app = keystone_app_factory(globex=True)
    alice, bob = fake_idp.token_for("alice"), fake_idp.token_for("bob")
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {alice}"}, timeout=15)
    async with http, Client(streamable_http_client(keystone_app.url, http_client=http)) as client:
        before = [t.name for t in (await client.list_tools()).tools]
        http.headers["Authorization"] = f"Bearer {bob}"  # the same session, another person
        with pytest.raises(MCPError) as swapped:
            await client.list_tools()
        http.headers["Authorization"] = f"Bearer {alice}"
        after = [t.name for t in (await client.list_tools()).tools]

    assert swapped.value.error.message == "session belongs to another principal"
    assert before == after and "echo__echo" in before


@pytest.mark.phase(3)
async def test_a_new_token_for_the_same_principal_keeps_the_session(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    session = open_session(keystone_app, fake_idp.token_for("alice"))

    refreshed = fake_idp.token_for("alice")  # a different token, the same tenant, user and agent
    response = request(keystone_app, refreshed, LIST_TOOLS, session=session)

    assert tool_count(response) > 0


@pytest.mark.phase(3)
async def test_the_same_user_through_another_agent_is_another_principal(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    session = open_session(keystone_app, fake_idp.token_for("olivia", agent="ops-agent"))

    ops = fake_idp.token_for("olivia", agent="ops-agent")
    support = fake_idp.token_for("olivia", agent="support-agent")
    same_agent = request(keystone_app, ops, LIST_TOOLS, session=session)
    other_agent = request(keystone_app, support, LIST_TOOLS, session=session)

    assert same_agent.status_code == 200
    assert other_agent.status_code == 403


@pytest.mark.phase(3)
async def test_a_session_id_nobody_opened_is_not_found(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    response = request(keystone_app, fake_idp.token_for("alice"), LIST_TOOLS, session="0" * 32)

    assert response.status_code == 404
    assert "Session not found" in response.text


@pytest.mark.phase(3)
async def test_a_session_nobody_bound_is_never_adopted_by_whoever_asks_first(
    keystone_app_factory: Callable[..., KeystoneApp], fake_idp: FakeIdp
) -> None:
    keystone_app = keystone_app_factory(globex=True)
    # The SDK still knows this session, but the gateway lost its binding (a restart of the
    # binding table, say). If the first caller to name it were bound to it, anybody who learned
    # the id could take the session over before its owner used it again.
    alice, bob = fake_idp.token_for("alice"), fake_idp.token_for("bob")
    session = open_session(keystone_app, alice)
    keystone_app.app.state.gateway.bindings.forget(session)

    by_bob = request(keystone_app, bob, LIST_TOOLS, session=session)
    by_alice = request(keystone_app, alice, LIST_TOOLS, session=session)

    assert by_bob.status_code == 404
    assert by_alice.status_code == 404


@pytest.mark.phase(3)
async def test_a_session_that_was_ended_cannot_be_used_again(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    alice = fake_idp.token_for("alice")
    session = open_session(keystone_app, alice)

    ended = request(keystone_app, alice, None, session=session, method="DELETE")
    again = request(keystone_app, alice, LIST_TOOLS, session=session)

    assert ended.status_code == 200
    assert again.status_code == 404


@pytest.mark.phase(3)
async def test_the_session_is_stored_with_its_principal_when_it_opens(
    keystone_app: KeystoneApp,
    fake_idp: FakeIdp,
    redis: Redis,
    sessionmaker: Sessions,
) -> None:
    session = open_session(keystone_app, fake_idp.token_for("olivia"))

    state = SessionState.model_validate_json(await redis.get(session_key(session)) or "")
    async with sessionmaker() as database:
        row = await database.get(McpSession, session)
    assert (state.principal.tenant_id, state.principal.user_id) == ("acme", "olivia")
    assert state.principal.agent_id == "ops-agent" and state.principal.agent_trust == "high"
    assert row is not None and (row.tenant_id, row.user_id, row.agent_id) == (
        "acme",
        "olivia",
        "ops-agent",
    )


@pytest.mark.phase(3)
async def test_a_call_carries_the_principal_of_its_own_token(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    async with mcp_client(keystone_app, user="olivia") as client:
        await client.call_tool("echo__echo", {"payload": "x"})
    async with mcp_client(keystone_app, user="alice") as client:
        await client.call_tool("echo__echo", {"payload": "y"})

    first, second = keystone_app.audit.records
    assert (first["user_id"], first["agent_id"]) == ("olivia", "ops-agent")
    assert (second["user_id"], second["agent_id"]) == ("alice", "support-agent")
    assert first["tenant_id"] == second["tenant_id"] == "acme"


@pytest.mark.phase(3)
async def test_a_call_never_runs_on_stored_state_that_belongs_to_someone_else(
    keystone_app: KeystoneApp,
    fake_idp: FakeIdp,
    redis: Redis,
    demo_upstreams: DemoUpstreams,
) -> None:
    # The middleware compares against who opened the session. The handler compares against the
    # stored state as well, so state that was changed behind the gateway's back is not trusted.
    alice = fake_idp.token_for("alice")
    session = open_session(keystone_app, alice)
    stored = SessionState.model_validate_json(await redis.get(session_key(session)) or "")
    forged = stored.model_copy(
        update={"principal": stored.principal.model_copy(update={"user_id": "bob"})}
    )
    await redis.set(session_key(session), forged.model_dump_json())
    call = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "echo__echo", "arguments": {"payload": "x"}},
    }

    response = request(keystone_app, alice, call, session=session)

    assert response.status_code == 200
    assert "KS_DENIED" in response.text and "session belongs to another principal" in response.text
    assert demo_upstreams.state("echo")["calls"] == []
    [record] = keystone_app.audit.records
    assert (record["outcome"], record["reject_code"], record["dispatched"]) == (
        "rejected",
        "KS_DENIED",
        False,
    )


@pytest.mark.phase(3)
async def test_a_refused_request_reaches_no_upstream_and_leaves_no_audit_record(
    keystone_app: KeystoneApp, demo_upstreams: DemoUpstreams
) -> None:
    call = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "echo__echo", "arguments": {"payload": "x"}},
    }

    refused = request(keystone_app, None, call, session="0" * 32)

    assert refused.status_code == 401
    assert demo_upstreams.state("echo")["calls"] == []
    assert keystone_app.audit.records == []
