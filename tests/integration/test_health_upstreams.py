"""KS-209: probes mark an upstream down, and calls to it fail fast."""

import time
from collections.abc import Callable
from pathlib import Path

import anyio
import httpx2
import pytest
from starlette.types import ASGIApp

from examples.upstreams import bank_server
from keystone.registry.config import UpstreamConfig
from keystone.settings import HealthSettings
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.servers import RestartableServer
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(2), pytest.mark.services]

FAST = HealthSettings(interval_s=0.2, timeout_s=1.0, degraded_after=1, down_after=3)


def bank_on_a_free_port(tmp_path: Path) -> RestartableServer:
    def make_app() -> ASGIApp:
        return bank_server.create_server(tmp_path / "bank.db").streamable_http_app()

    return RestartableServer(make_app)


def readyz(app: KeystoneApp) -> httpx2.Response:
    return httpx2.get(f"{app.base}/readyz", timeout=10)


async def wait_for_status(
    app: KeystoneApp, upstream: str, status: str, seconds: float = 20
) -> None:
    with anyio.fail_after(seconds):
        while readyz(app).json()["upstreams"].get(upstream) != status:  # noqa: ASYNC110
            await anyio.sleep(0.1)


def upstreams_for(demo: DemoUpstreams, bank: RestartableServer) -> list[UpstreamConfig]:
    entries = [UpstreamConfig(id="mail", tenant="acme", url=demo.url("mail"))]
    return [*entries, UpstreamConfig(id="bank", tenant="acme", url=bank.url)]


async def test_upstream_down_fails_fast(
    start_keystone: Callable[..., KeystoneApp],
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    tmp_path: Path,
) -> None:
    bank = bank_on_a_free_port(tmp_path).start()
    try:
        app = start_keystone(upstreams_for(demo_upstreams, bank), health=FAST)
        async with mcp_client(app) as client:
            healthy = await client.call_tool("bank__get_balance", {"account": "CHK-001"})
            assert not healthy.is_error

            bank.stop()
            await wait_for_status(app, "bank", "down")

            # Now the gateway knows. The call must come back without a connection attempt.
            timings: list[float] = []
            for _ in range(5):
                started = time.perf_counter()
                refused = await client.call_tool("bank__get_balance", {"account": "CHK-001"})
                timings.append((time.perf_counter() - started) * 1000)
            other = await client.call_tool("mail__list_emails", {"folder": "inbox"})
    finally:
        bank.stop()

    assert refused.is_error
    assert refused.meta is not None and refused.meta["keystone/code"] == "KS_UPSTREAM_ERROR"
    [block] = refused.content
    assert "upstream bank is down" in getattr(block, "text", "")
    assert min(timings) < 50, f"the refusal took {min(timings):.1f} ms at best: {timings}"
    # The other upstream carries on.
    assert not other.is_error
    record = app.audit.records[-2]  # the refused call, before the mail call
    assert (record["tool"], record["outcome"], record["dispatched"]) == (
        "bank__get_balance",
        "error",
        False,
    )


async def test_an_upstream_that_comes_back_is_used_again(
    start_keystone: Callable[..., KeystoneApp],
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    tmp_path: Path,
) -> None:
    bank = bank_on_a_free_port(tmp_path).start()
    try:
        app = start_keystone(upstreams_for(demo_upstreams, bank), health=FAST)
        async with mcp_client(app) as client:
            await client.call_tool("bank__get_balance", {"account": "CHK-001"})
            bank.stop()
            await wait_for_status(app, "bank", "down")

            bank.start()
            await wait_for_status(app, "bank", "up")
            result = await client.call_tool("bank__get_balance", {"account": "CHK-001"})
    finally:
        bank.stop()

    assert not result.is_error


async def test_readyz_includes_upstreams(
    start_keystone: Callable[..., KeystoneApp],
    demo_upstreams: DemoUpstreams,
    tmp_path: Path,
) -> None:
    bank = bank_on_a_free_port(tmp_path).start()
    try:
        app = start_keystone(upstreams_for(demo_upstreams, bank), health=FAST)
        await wait_for_status(app, "bank", "up")
        all_up = readyz(app)

        bank.stop()
        await wait_for_status(app, "bank", "down")
        one_down = readyz(app)
    finally:
        bank.stop()

    assert all_up.status_code == 200
    assert all_up.json() == {
        "status": "ok",
        "dependencies": {"database": "ok", "redis": "ok"},
        "upstreams": {"bank": "up", "mail": "up"},
    }
    # An upstream that is down does not make Keystone unready: only Postgres and Redis do.
    assert one_down.status_code == 200
    assert one_down.json()["upstreams"] == {"bank": "down", "mail": "up"}


async def test_a_disabled_upstream_is_left_out_of_readyz(
    start_keystone: Callable[..., KeystoneApp],
    demo_upstreams: DemoUpstreams,
) -> None:
    app = start_keystone([UpstreamConfig(id="mail", tenant="acme", url=demo_upstreams.url("mail"))])
    first = readyz(app).json()["upstreams"]
    app2 = start_keystone(
        [UpstreamConfig(id="echo", tenant="acme", url=demo_upstreams.url("echo"))]
    )
    second = readyz(app2).json()["upstreams"]

    assert first == {"mail": "up"}
    # mail left the config at the second start, so it is disabled and not listed.
    assert second == {"echo": "up"}


async def test_with_the_probes_off_nothing_is_ever_marked_down(
    start_keystone: Callable[..., KeystoneApp],
    demo_upstreams: DemoUpstreams,
    tmp_path: Path,
) -> None:
    bank = bank_on_a_free_port(tmp_path).start()
    try:
        app = start_keystone(upstreams_for(demo_upstreams, bank))  # interval_s=0
        bank.stop()
        await anyio.sleep(1.5)
        statuses = readyz(app).json()["upstreams"]
    finally:
        bank.stop()

    assert statuses["bank"] == "up"
