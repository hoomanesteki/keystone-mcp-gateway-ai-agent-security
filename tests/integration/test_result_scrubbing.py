"""KS-392: an upstream that returns the credential it received does not hand it to the agent.

The upstream is test-only (tests/fixtures/reflecting_upstream.py). It requires its API key, and
three of its tools return that key as a nested structure, inside a sentence and as a plain value.
The agent asks Keystone for each and must see `[redacted]` where the key was.
"""

import io
import logging
import secrets
from collections.abc import Callable, Iterator
from typing import Any

import httpx2
import pytest
import structlog
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from keystone.logging import REDACTED, SECRETS, configure_logging, register_secret
from keystone.registry.config import UpstreamConfig
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.mcp_results import one, texts
from tests.fixtures.reflecting_upstream import reflecting_upstream
from tests.fixtures.servers import ServerThread

pytestmark = [pytest.mark.phase(4), pytest.mark.services]

Factory = Callable[..., KeystoneApp]


@pytest.fixture
def key() -> str:
    return f"reflect-key-{secrets.token_hex(12)}"


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    configure_logging("DEBUG", stream=buffer)
    yield buffer
    structlog.reset_defaults()


def start(factory: Factory, upstream: ServerThread, key: str) -> KeystoneApp:
    config = UpstreamConfig(
        id="reflect",
        tenant="acme",
        url=f"{upstream.url}/mcp",
        credential_mode="static",
        credential_env={"X-Api-Key": "REFLECT_API_KEY"},
    )
    return factory(settings={"upstreams": [config]}, environ={"REFLECT_API_KEY": key})


async def test_the_upstream_really_returns_its_key_when_it_is_asked_directly(
    key: str,
) -> None:
    # The control: without Keystone in between, the key comes back. Every other test in this file
    # would pass for the wrong reason if the upstream never reflected it.
    with reflecting_upstream(key) as upstream:
        async with (
            httpx2.AsyncClient(headers={"X-Api-Key": key}) as http,
            Client(streamable_http_client(f"{upstream.url}/mcp", http_client=http)) as client,
        ):
            direct = await client.call_tool("show_key", {})

    assert one(direct)["received"] == key


async def test_the_key_comes_back_redacted_in_text_and_structured_content(
    keystone_app_factory: Factory, mcp_client: McpConnect, key: str
) -> None:
    with reflecting_upstream(key) as upstream:
        app = start(keystone_app_factory, upstream, key)
        async with mcp_client(app) as client:
            shown = await client.call_tool("reflect__show_key", {})
            shouted = await client.call_tool("reflect__shout", {"note": "debug"})

    assert not shown.is_error and not shouted.is_error
    assert one(shown) == {"received": REDACTED, "nested": {"headers": [f"X-Api-Key: {REDACTED}"]}}
    assert shown.structured_content == one(shown)
    assert texts(shouted) == [f"debug: the key I was sent is {REDACTED}"]
    for result in (shown, shouted):
        assert key not in result.model_dump_json(by_alias=True)


async def test_the_call_is_audited_as_a_success_and_the_record_holds_no_key(
    keystone_app_factory: Factory, mcp_client: McpConnect, key: str
) -> None:
    with reflecting_upstream(key) as upstream:
        app = start(keystone_app_factory, upstream, key)
        async with mcp_client(app) as client:
            await client.call_tool("reflect__show_key", {})

    [record] = app.audit.records
    assert (record["tool_name"], record["outcome"], record["dispatched"]) == (
        "reflect__show_key",
        "ok",
        True,
    )
    assert key not in repr(record)


async def test_a_secret_held_for_another_upstream_is_redacted_too(
    keystone_app_factory: Factory, mcp_client: McpConnect, key: str
) -> None:
    other = f"other-upstream-key-{secrets.token_hex(8)}"
    with reflecting_upstream(key, extra=other) as upstream:
        app = start(keystone_app_factory, upstream, key)
        # The vault registers each credential it decrypts, so by now Keystone has seen this one.
        register_secret(other)
        try:
            async with mcp_client(app) as client:
                result = await client.call_tool("reflect__show_extra", {})
        finally:
            SECRETS.clear()

    assert one(result) == {"extra": REDACTED}
    assert other not in result.model_dump_json(by_alias=True)


async def test_an_echoed_credential_is_logged_without_the_value(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    key: str,
    log_buffer: io.StringIO,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    with reflecting_upstream(key) as upstream:
        app = start(keystone_app_factory, upstream, key)
        async with mcp_client(app) as client:
            await client.call_tool("reflect__shout", {"note": "debug"})

    logs = log_buffer.getvalue()
    assert "upstream_result_redacted" in logs  # an operator can see which upstream echoes keys
    assert "reflect__shout" in logs
    assert key not in logs and key not in caplog.text


async def test_a_result_with_no_credential_in_it_is_passed_on_as_it_is(
    keystone_app_factory: Factory, mcp_client: McpConnect, key: str, log_buffer: io.StringIO
) -> None:
    with reflecting_upstream(key, extra="a plain value") as upstream:
        app = start(keystone_app_factory, upstream, key)
        async with mcp_client(app) as client:
            result = await client.call_tool("reflect__show_extra", {})

    assert one(result) == {"extra": "a plain value"}
    assert "upstream_result_redacted" not in log_buffer.getvalue()


async def test_the_scrub_is_what_removes_the_key(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The same call with the scrub switched off: the key reaches the agent, so the tests above
    # would notice a dispatcher that stopped scrubbing.
    def identity(result: Any, injected: Any = ()) -> Any:
        return result

    monkeypatch.setattr("keystone.gateway.dispatch.scrub_result", identity)
    with reflecting_upstream(key) as upstream:
        app = start(keystone_app_factory, upstream, key)
        async with mcp_client(app) as client:
            result = await client.call_tool("reflect__show_key", {})

    assert one(result)["received"] == key
