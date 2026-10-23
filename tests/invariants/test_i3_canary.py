"""I3: a canary secret never appears in logs, audit records, error messages or tool results.

The canary is the real API key of the echo server, stored in the vault and sent with every call
to it. A session then does what goes wrong in practice: a call that works, an upstream that
returns the key it received (a test-only upstream, tests/fixtures/reflecting_upstream.py), an
upstream that reports an error, an upstream that is too slow, a refusal by policy, arguments that
do not fit, a tool that does not exist, and a dispatch that fails with an exception whose text
holds the request headers, the way a careless HTTP library's can. Everything an observer could
read is then searched for the canary: Keystone's logs (structlog and the standard library), the
audit records, and every result and rejection the agent received.

Since KS-504 the spans are searched too: the app runs with a tracer that keeps its spans in memory,
and every name, attribute, event and status in them is part of what an observer could read.
"""

import io
import json
import logging
from collections.abc import Callable, Iterator
from typing import Any

import pytest
import structlog

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect, ToolResult
from keystone.gateway.pipeline import Dispatcher
from keystone.logging import SECRETS, configure_logging
from keystone.registry.config import ToolOverride, UpstreamConfig
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.reflecting_upstream import reflecting_upstream
from tests.fixtures.servers import ServerThread
from tests.fixtures.tracing import dump, traced
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(3), pytest.mark.services]

Factory = Callable[..., KeystoneApp]


class Policy:
    """A policy slot that allows every call but one, which it refuses."""

    name = "policy"

    async def before_call(self, ctx: CallContext) -> None:
        if ctx.arguments.get("payload") == "forbidden":
            raise Reject(Code.DENIED, "policy says no")
        ctx.decision = Decision(effect=Effect.ALLOW, source="policy")

    async def after_call(self, ctx: CallContext) -> None:
        return None


class LeakyDispatcher:
    """Fails one call the way a careless library can: with the request headers in the message."""

    def __init__(self, inner: Dispatcher) -> None:
        self.inner = inner

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        if ctx.arguments.get("payload") == "leak":
            sent = {name: value.get_secret_value() for name, value in ctx.upstream_headers.items()}
            raise RuntimeError(f"the upstream refused the request, headers were {sent}")
        return await self.inner.dispatch(ctx)


@pytest.fixture(autouse=True)
def fresh_registry() -> Iterator[None]:
    """Start with no secret registered, so any protection comes from this test's own calls."""
    SECRETS.clear()
    yield
    SECRETS.clear()


@pytest.fixture
def log_buffer(caplog: pytest.LogCaptureFixture) -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    configure_logging("DEBUG", stream=buffer)
    caplog.set_level(logging.DEBUG)
    yield buffer
    structlog.reset_defaults()


@pytest.fixture
def reflector(canary_secret: str) -> Iterator[ServerThread]:
    """The test-only upstream that returns the key it received. Its key is the canary."""
    with reflecting_upstream(canary_secret) as thread:
        yield thread


def reflect_upstream(thread: ServerThread) -> UpstreamConfig:
    # Same variable as the echo upstream's, so Keystone sends it the same canary.
    return UpstreamConfig(
        id="reflect",
        tenant="acme",
        url=f"{thread.url}/mcp",
        credential_mode="static",
        credential_env={"X-Api-Key": "ECHO_API_KEY"},
    )


def echo_upstream(keyed: DemoUpstreams) -> UpstreamConfig:
    return UpstreamConfig(
        id="echo",
        tenant="acme",
        url=keyed.url("echo"),
        credential_mode="static",
        credential_env={"X-Api-Key": "ECHO_API_KEY"},
        # The sleep tool gives up after half a second, so the timeout path is quick to reach.
        tools={"sleep": ToolOverride(timeout_s=0.5)},
    )


SESSION: list[tuple[str, dict[str, Any]]] = [
    ("echo__echo", {"payload": "hello"}),  # works
    ("reflect__show_key", {}),  # the upstream returns the key it received (KS-392)
    ("reflect__shout", {"note": "debug"}),  # and so does this one, inside a sentence
    ("echo__fail", {"message": "on purpose"}),  # the upstream reports an error
    ("echo__sleep", {"seconds": 5}),  # the upstream is too slow
    ("echo__echo", {"payload": "forbidden"}),  # policy refuses
    ("echo__echo", {"payload": 7}),  # arguments do not fit the schema
    ("echo__nothing", {}),  # no such tool
    ("echo__echo", {"payload": "leak"}),  # dispatch fails with the headers in its message
    ("keystone__whoami", {}),  # says who the caller is, and holds no token or credential (KS-603)
]


async def run_session(app: KeystoneApp, mcp_client: McpConnect) -> list[str]:
    """Every result the agent received, as the JSON the wire carries, `_meta` included."""
    received: list[str] = []
    async with mcp_client(app) as client:
        received.append((await client.list_tools()).model_dump_json(by_alias=True))
        for tool, arguments in SESSION:
            received.append(
                (await client.call_tool(tool, arguments)).model_dump_json(by_alias=True)
            )
    return received


def started(
    factory: Factory, keyed: DemoUpstreams, reflector: ServerThread, **options: Any
) -> KeystoneApp:
    return factory(
        keyed=True,
        settings={"upstreams": [echo_upstream(keyed), reflect_upstream(reflector)]},
        interceptors={"policy": Policy()},
        wrap_dispatcher=LeakyDispatcher,
        **options,
    )


async def test_i3(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    keyed_upstreams: DemoUpstreams,
    reflector: ServerThread,
    canary_secret: str,
    log_buffer: io.StringIO,
    caplog: pytest.LogCaptureFixture,
) -> None:
    tracer, exporter = traced()
    app = started(keystone_app_factory, keyed_upstreams, reflector, tracer=tracer)
    # The startup stored and read the credential. Forget everything the scrubber learned from it,
    # so that what protects the session below is the vault registering each secret it decrypts.
    SECRETS.clear()

    received = await run_session(app, mcp_client)

    logs = log_buffer.getvalue()
    observed = {
        "structlog output": logs,
        "standard library logs": caplog.text,
        "audit records": json.dumps(app.audit.records, default=str),
        "results and rejections": "\n".join(received),
        "spans": dump(exporter.get_finished_spans()),
    }
    # The search is only worth something if the session really happened and really logged.
    assert keyed_upstreams.state("echo")["api_key_received"] is True  # the canary was sent
    assert [(r["tool_name"], r["outcome"]) for r in app.audit.records] == [
        ("echo__echo", "ok"),
        ("reflect__show_key", "ok"),
        ("reflect__shout", "ok"),
        ("echo__fail", "ok"),  # the call itself worked; the upstream's answer was an error
        ("echo__sleep", "error"),
        ("echo__echo", "rejected"),
        ("echo__echo", "rejected"),
        ("echo__nothing", "rejected"),
        ("echo__echo", "error"),
        ("keystone__whoami", "ok"),
    ]
    codes = [json.loads(r).get("_meta", {}).get("keystone/code") for r in received[1:]]
    assert codes == [
        None,
        None,
        None,
        None,
        "KS_UPSTREAM_TIMEOUT",
        "KS_DENIED",
        "KS_INVALID_ARGUMENTS",
        "KS_TOOL_NOT_FOUND",
        "KS_UPSTREAM_ERROR",
        None,
    ]
    # The last call asked who the caller is: the answer names the principal and holds no secret.
    who = json.loads(received[-1])["structuredContent"]
    assert who["principal"]["user_id"] == "alice" and who["principal"]["tenant_id"] == "acme"
    assert "startup_sync" in logs and "dispatch_failed" in logs
    assert (
        "keystone.tool_call" in observed["spans"] and "keystone.upstream.call" in observed["spans"]
    )
    assert "[redacted]" in logs  # the exception that held the headers was masked, not absent
    # The reflecting upstream did return the key; what the agent got in its place is the marker.
    for shown in received[2:4]:
        assert json.loads(shown)["isError"] is False and shown.count("[redacted]") >= 2

    for where, text in observed.items():
        assert canary_secret not in text, f"the canary is in the {where}"
    for key in keyed_upstreams.keys.values():
        assert key not in "".join(observed.values())


async def test_the_canary_search_can_fail(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    keyed_upstreams: DemoUpstreams,
    reflector: ServerThread,
    canary_secret: str,
    log_buffer: io.StringIO,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The same session with the scrubber's registry switched off: the exception that holds the
    # headers now reaches the log, which shows test_i3 would notice a leak.
    monkeypatch.setattr("keystone.identity.vault.register_secret", lambda value: False)
    app = started(keystone_app_factory, keyed_upstreams, reflector)

    async with mcp_client(app) as client:
        result = await client.call_tool("echo__echo", {"payload": "leak"})

    assert result.is_error
    assert canary_secret in log_buffer.getvalue()
    assert canary_secret not in result.model_dump_json(by_alias=True)  # the agent still sees none


@pytest.mark.phase(4)
async def test_the_result_search_can_fail(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    keyed_upstreams: DemoUpstreams,
    reflector: ServerThread,
    canary_secret: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The same upstream with the dispatcher's scrub switched off: the canary reaches the agent in
    # the text block and in the structured content, which shows test_i3 would notice it.
    def keep(result: ToolResult, injected: Any = ()) -> ToolResult:
        return result

    monkeypatch.setattr("keystone.gateway.dispatch.scrub_result", keep)
    app = started(keystone_app_factory, keyed_upstreams, reflector)

    async with mcp_client(app) as client:
        result = await client.call_tool("reflect__show_key", {})

    assert not result.is_error
    assert result.structured_content is not None
    assert result.structured_content["received"] == canary_secret
    assert canary_secret in result.model_dump_json(by_alias=True)


@pytest.mark.phase(5)
def test_the_span_search_can_fail(canary_secret: str) -> None:
    # A span that does hold the canary, in an attribute or in an exception recorded on it, is found.
    tracer, exporter = traced()

    with tracer.span("keystone.upstream.call", {"keystone.upstream": canary_secret}):
        pass
    with pytest.raises(RuntimeError), tracer._tracer.start_as_current_span("leaky"):
        raise RuntimeError(f"the upstream refused {canary_secret}")

    found = dump(exporter.get_finished_spans())
    assert found.count(canary_secret) >= 2  # the attribute, and the exception's text
