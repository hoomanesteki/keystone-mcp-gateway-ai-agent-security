"""KS-504 through the running gateway: the agent's trace is continued, the audit row names the
trace, and the upstream receives the trace context."""

from collections.abc import Callable, Iterator

import pytest

from keystone.registry.config import UpstreamConfig
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.reflecting_upstream import reflecting_upstream
from tests.fixtures.servers import ServerThread
from tests.fixtures.tracing import named, traced

pytestmark = [pytest.mark.phase(5), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT_SPAN_ID = "00f067aa0ba902b7"
TRACEPARENT = f"00-{TRACE_ID}-{PARENT_SPAN_ID}-01"


async def test_incoming_traceparent_continued(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    tracer, exporter = traced()
    app = keystone_app_factory(tracer=tracer)

    async with mcp_client(app, headers={"traceparent": TRACEPARENT}) as client:
        result = await client.call_tool("echo__echo", {"payload": "hi"})

    assert not result.is_error
    spans = exporter.get_finished_spans()
    [root] = named(spans, "keystone.tool_call")
    assert format(root.context.trace_id, "032x") == TRACE_ID
    assert root.parent is not None and root.parent.is_remote
    assert format(root.parent.span_id, "016x") == PARENT_SPAN_ID
    # The stages of the call are in the agent's trace too.
    assert len(spans) > 9
    assert {span.context.trace_id for span in spans} == {root.context.trace_id}


async def test_a_call_without_a_traceparent_starts_its_own_trace(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    tracer, exporter = traced()
    app = keystone_app_factory(tracer=tracer)

    async with mcp_client(app) as client:
        await client.call_tool("echo__echo", {"payload": "one"})
        await client.call_tool("echo__echo", {"payload": "two"})

    first, second = named(exporter.get_finished_spans(), "keystone.tool_call")
    assert first.parent is None and second.parent is None
    assert first.context.trace_id != second.context.trace_id


async def test_audit_row_has_trace_id(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    tracer, exporter = traced()
    app = keystone_app_factory(tracer=tracer)

    async with mcp_client(app) as client:  # alice
        await client.call_tool("echo__echo", {"payload": "ok"})
        await client.call_tool("echo__nothing", {})  # a tool that does not exist
        await client.call_tool(
            "bank__transfer", {"from_account": "CHK-001", "to": "SAV-002", "amount": 5}
        )  # denied by policy

    roots = named(exporter.get_finished_spans(), "keystone.tool_call")
    rows = app.audit.records
    assert len(roots) == len(rows) == 3
    assert [row["trace_id"] for row in rows] == [format(r.context.trace_id, "032x") for r in roots]
    assert len({row["trace_id"] for row in rows}) == 3
    # The refusals have a root span too, with the code that refused them.
    codes = [dict(root.attributes or {}).get("keystone.reject_code") for root in roots]
    assert [(row["outcome"], code) for row, code in zip(rows, codes, strict=True)] == [
        ("ok", None),
        ("rejected", "KS_TOOL_NOT_FOUND"),
        ("rejected", "KS_DENIED"),
    ]


async def test_a_gateway_without_tracing_writes_no_trace_id(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    async with mcp_client(keystone_app) as client:
        await client.call_tool("echo__echo", {"payload": "ok"})

    [row] = keystone_app.audit.records
    assert row["trace_id"] is None


@pytest.fixture
def reflector(canary_secret: str) -> Iterator[ServerThread]:
    with reflecting_upstream(canary_secret) as thread:
        yield thread


def reflect_upstream(thread: ServerThread) -> UpstreamConfig:
    # The same variable as the echo upstream's key, so Keystone sends the key the server wants.
    return UpstreamConfig(
        id="reflect",
        tenant="acme",
        url=f"{thread.url}/mcp",
        credential_mode="static",
        credential_env={"X-Api-Key": "ECHO_API_KEY"},
    )


async def test_the_trace_context_reaches_the_upstream_in_meta(
    keystone_app_factory: Factory, mcp_client: McpConnect, reflector: ServerThread
) -> None:
    tracer, exporter = traced()
    app = keystone_app_factory(
        keyed=True, settings={"upstreams": [reflect_upstream(reflector)]}, tracer=tracer
    )

    async with mcp_client(app, headers={"traceparent": TRACEPARENT}) as client:
        result = await client.call_tool("reflect__show_meta", {})

    assert not result.is_error and result.structured_content is not None
    sent = result.structured_content["meta"]["traceparent"]
    version, trace_id, span_id, flags = sent.split("-")
    [upstream] = named(exporter.get_finished_spans(), "keystone.upstream.call")
    # The upstream's parent is the span Keystone opened for the call, in the agent's trace.
    assert (version, trace_id) == ("00", TRACE_ID)
    assert span_id == format(upstream.context.span_id, "016x")
    assert int(flags, 16) & 1


async def test_no_trace_context_is_sent_when_tracing_is_off(
    keystone_app_factory: Factory, mcp_client: McpConnect, reflector: ServerThread
) -> None:
    app = keystone_app_factory(keyed=True, settings={"upstreams": [reflect_upstream(reflector)]})

    async with mcp_client(app, headers={"traceparent": TRACEPARENT}) as client:
        result = await client.call_tool("reflect__show_meta", {})

    assert not result.is_error and result.structured_content is not None
    assert "traceparent" not in result.structured_content["meta"]
