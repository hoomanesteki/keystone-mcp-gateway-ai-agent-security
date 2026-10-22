import json
import time
from pathlib import Path
from typing import Any

import anyio
import pytest
from pydantic import SecretStr

from examples.upstreams import _common, echo_server
from keystone.core.errors import Code, Reject
from keystone.gateway.upstreams import HttpUpstreamClient, UpstreamPool, http_client_factory
from tests.fixtures.servers import ServerThread
from tests.fixtures.upstreams import DemoUpstreams

FAST_BACKOFF = (0.05, 0.05, 0.05)


def text_of(blocks: list[dict[str, Any]]) -> str:
    return "".join(str(block.get("text", "")) for block in blocks)


async def connect(tg: anyio.abc.TaskGroup, url: str, **options: Any) -> HttpUpstreamClient:
    return HttpUpstreamClient(url, {}, tg, upstream_id="echo", **options)


@pytest.mark.phase(1)
async def test_call_tool_roundtrip(demo_upstreams: DemoUpstreams) -> None:
    async with anyio.create_task_group() as tg:
        client = await connect(tg, demo_upstreams.url("echo"))
        try:
            result = await client.call_tool("echo", {"payload": "ping"}, timeout_s=5)
            tools = await client.list_tools()
            healthy = await client.health()
        finally:
            await client.aclose()

    assert result.is_error is False
    assert text_of(result.content) == "ping"
    assert result.structured_content == {"result": "ping"}
    assert {t.name for t in tools} == {"echo", "sleep", "fail"}
    assert next(t for t in tools if t.name == "echo").input_schema["required"] == ["payload"]
    assert healthy is True


@pytest.mark.phase(1)
async def test_timeout_maps_to_upstream_timeout(demo_upstreams: DemoUpstreams) -> None:
    async with anyio.create_task_group() as tg:
        client = await connect(tg, demo_upstreams.url("echo"))
        try:
            started = time.monotonic()
            with pytest.raises(Reject) as raised:
                await client.call_tool("sleep", {"seconds": 5}, timeout_s=1)
            elapsed = time.monotonic() - started
            # The session survives a timed-out call.
            after = await client.call_tool("echo", {"payload": "still here"}, timeout_s=5)
        finally:
            await client.aclose()

    assert raised.value.code is Code.UPSTREAM_TIMEOUT
    assert 0.9 < elapsed < 2.0
    assert text_of(after.content) == "still here"


@pytest.mark.phase(1)
@pytest.mark.parametrize("protocol", ["auto", "legacy"])
async def test_reconnect_after_upstream_restart(protocol: str) -> None:
    upstream = ServerThread(echo_server.create_server().streamable_http_app()).start()
    port = upstream.port
    url = f"{upstream.url}/mcp"
    try:
        async with anyio.create_task_group() as tg:
            client = await connect(tg, url, protocol=protocol, backoff_s=FAST_BACKOFF)
            try:
                first = await client.call_tool("echo", {"payload": "one"}, timeout_s=5)
                upstream.stop()
                upstream = ServerThread(
                    echo_server.create_server().streamable_http_app(), port=port
                ).start()
                second = await client.call_tool("echo", {"payload": "two"}, timeout_s=5)
                third = await client.call_tool("echo", {"payload": "three"}, timeout_s=5)
            finally:
                await client.aclose()
    finally:
        upstream.stop()

    assert [text_of(r.content) for r in (first, second, third)] == ["one", "two", "three"]


@pytest.mark.phase(1)
async def test_a_call_in_flight_when_the_upstream_dies_fails_without_a_retry() -> None:
    # The tool may have run already, so resending it (a transfer, an email) could do it twice.
    upstream = ServerThread(echo_server.create_server().streamable_http_app()).start()
    try:
        async with anyio.create_task_group() as tg:
            client = await connect(tg, f"{upstream.url}/mcp", backoff_s=FAST_BACKOFF)
            try:
                await client.call_tool("echo", {"payload": "warm up"}, timeout_s=5)

                async def kill_soon() -> None:
                    await anyio.sleep(0.3)
                    await anyio.to_thread.run_sync(upstream.stop)

                tg.start_soon(kill_soon)
                with pytest.raises(Reject) as raised:
                    await client.call_tool("sleep", {"seconds": 5}, timeout_s=10)
            finally:
                await client.aclose()
    finally:
        upstream.stop()

    assert raised.value.code in (Code.UPSTREAM_ERROR, Code.UPSTREAM_TIMEOUT)


@pytest.mark.phase(1)
async def test_an_unreachable_upstream_gives_upstream_error_after_the_backoff() -> None:
    upstream = ServerThread(echo_server.create_server().streamable_http_app()).start()
    url = f"{upstream.url}/mcp"
    port = upstream.port
    upstream.stop()

    async with anyio.create_task_group() as tg:
        client = await connect(tg, url, backoff_s=FAST_BACKOFF)
        started = time.monotonic()
        try:
            with pytest.raises(Reject) as raised:
                await client.call_tool("echo", {"payload": "x"}, timeout_s=10)
        finally:
            await client.aclose()

    assert raised.value.code is Code.UPSTREAM_ERROR
    assert 0.1 < time.monotonic() - started < 5
    # The message carries no address, header or exception text.
    assert str(raised.value.message) == "the upstream server is not reachable"
    assert str(port) not in raised.value.message


@pytest.mark.phase(1)
async def test_the_default_backoff_is_0_2_0_8_and_3_2_seconds() -> None:
    from keystone.gateway.upstreams import RECONNECT_BACKOFF_S

    assert RECONNECT_BACKOFF_S == (0.2, 0.8, 3.2)


@pytest.mark.phase(1)
async def test_a_tool_error_is_a_result_not_a_reject(demo_upstreams: DemoUpstreams) -> None:
    async with anyio.create_task_group() as tg:
        client = await connect(tg, demo_upstreams.url("echo"))
        try:
            failed = await client.call_tool("fail", {"message": "on purpose"}, timeout_s=5)
            unknown = await client.call_tool("no_such_tool", {}, timeout_s=5)
        finally:
            await client.aclose()

    assert failed.is_error
    assert "on purpose" in text_of(failed.content)
    assert unknown.is_error


@pytest.mark.phase(1)
async def test_concurrent_calls_share_one_session(demo_upstreams: DemoUpstreams) -> None:
    answers: list[str] = []

    async with anyio.create_task_group() as tg:
        client = await connect(tg, demo_upstreams.url("echo"))

        async def one(i: int) -> None:
            result = await client.call_tool("echo", {"payload": f"call-{i}"}, timeout_s=10)
            answers.append(text_of(result.content))

        try:
            async with anyio.create_task_group() as calls:
                for i in range(25):
                    calls.start_soon(one, i)
        finally:
            await client.aclose()

    assert sorted(answers) == sorted(f"call-{i}" for i in range(25))


@pytest.mark.phase(1)
async def test_headers_reach_the_upstream_and_a_wrong_key_is_refused(tmp_path: Path) -> None:
    app = _common.http_app(echo_server.create_server(), api_key="s3cret", host="127.0.0.1")
    upstream = ServerThread(app).start()
    url = f"{upstream.url}/mcp"
    try:
        async with UpstreamPool(http_client_factory({"echo": url}, backoff_s=FAST_BACKOFF)) as pool:
            good = await pool.get("echo", {"X-Api-Key": SecretStr("s3cret")})
            bad = await pool.get("echo", {"X-Api-Key": SecretStr("not-the-key")})
            answer = await good.call_tool("echo", {"payload": "hi"}, timeout_s=10)
            with pytest.raises(Reject) as raised:
                await bad.call_tool("echo", {"payload": "hi"}, timeout_s=10)
    finally:
        upstream.stop()

    assert text_of(answer.content) == "hi"
    assert raised.value.code is Code.UPSTREAM_ERROR
    assert "not-the-key" not in json.dumps([raised.value.message, raised.value.data])


@pytest.mark.phase(1)
async def test_closing_twice_is_fine_and_a_closed_client_refuses_calls(
    demo_upstreams: DemoUpstreams,
) -> None:
    async with anyio.create_task_group() as tg:
        client = await connect(tg, demo_upstreams.url("echo"))
        await client.call_tool("echo", {"payload": "x"}, timeout_s=5)
        await client.aclose()
        await client.aclose()
        with pytest.raises(Reject) as raised:
            await client.call_tool("echo", {"payload": "x"}, timeout_s=5)

    assert raised.value.code is Code.UPSTREAM_ERROR
    assert await client.health() is False


@pytest.mark.phase(1)
async def test_the_pool_builds_http_clients_by_upstream_id(demo_upstreams: DemoUpstreams) -> None:
    urls = {"echo": demo_upstreams.url("echo"), "mail": demo_upstreams.url("mail")}

    async with UpstreamPool(http_client_factory(urls)) as pool:
        echo = await pool.get("echo", None)
        mail = await pool.get("mail", None)
        echoed = await echo.call_tool("echo", {"payload": "pool"}, timeout_s=5)
        listed = await mail.call_tool("list_emails", {"folder": "sent"}, timeout_s=5)
        with pytest.raises(ValueError, match="unknown upstream"):
            await pool.get("nope", None)

    assert text_of(echoed.content) == "pool"
    assert len(texts_from(listed.content)) == 2


@pytest.mark.phase(2)
async def test_a_call_finishes_when_its_client_is_evicted_mid_call(
    demo_upstreams: DemoUpstreams,
) -> None:
    urls = {"echo": demo_upstreams.url("echo"), "mail": demo_upstreams.url("mail")}
    answers: list[Any] = []

    async def slow_call(pool: UpstreamPool) -> None:
        async with pool.lease("echo", None) as client:
            answers.append(await client.call_tool("sleep", {"seconds": 1}, timeout_s=10))

    async with (
        UpstreamPool(http_client_factory(urls), max_clients=1) as pool,
        anyio.create_task_group() as tg,
    ):
        tg.start_soon(slow_call, pool)
        await anyio.sleep(0.4)
        # One slot only: this evicts the echo client while its sleep call is running.
        async with pool.lease("mail", None) as mail:
            assert {t.name for t in await mail.list_tools()} >= {"send_email"}

    [answer] = answers
    assert answer.is_error is False
    assert text_of(answer.content) == "slept 1"


def texts_from(blocks: list[dict[str, Any]]) -> list[str]:
    return [str(b["text"]) for b in blocks if b.get("type") == "text"]
