"""Keystone must not change what an agent gets back from an upstream.

The same eight calls run twice, once straight at the upstreams and once through Keystone, with
a /_reset between the runs. Nothing is normalized: no result holds a timestamp or a random id.
Mail and transfer ids are sequence numbers (s1, t1) that /_reset restarts, and the seeded
dates are fixed. If a later phase adds a field that varies, normalize that field here and say so.
"""

from typing import Any

import pytest
from mcp import Client

from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.upstreams import DemoUpstreams

# (upstream, tool, arguments). The order matters: the transfer changes the balance that a later
# run would see, so both runs apply the same changes in the same order.
CALLS: list[tuple[str, str, dict[str, Any]]] = [
    ("mail", "list_emails", {"unread_only": True}),
    ("mail", "read_email", {"email_id": "m05"}),
    ("mail", "send_email", {"to": "colleague@acme.test", "subject": "Hi", "body": "Hello"}),
    ("files", "read_file", {"path": "reports/q3-summary.csv"}),
    ("files", "read_file", {"path": "../etc/passwd"}),  # an error result must match too
    ("bank", "get_balance", {"account": "SAV-002"}),
    ("bank", "transfer", {"from_account": "CHK-001", "to": "SAV-002", "amount": 25.5}),
    ("echo", "echo", {"payload": "equivalence"}),
]


def blocks(result: Any) -> list[dict[str, Any]]:
    return [b.model_dump(by_alias=True, mode="json") for b in result.content]


@pytest.mark.services
@pytest.mark.phase(1)
async def test_direct_vs_gateway_identical(
    keystone_app: KeystoneApp, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    direct = []
    for upstream, tool, arguments in CALLS:
        async with Client(demo_upstreams.url(upstream)) as client:
            result = await client.call_tool(tool, arguments)
        direct.append((result.is_error, blocks(result)))
    direct_state = {name: demo_upstreams.state(name) for name in ("mail", "bank", "files")}

    demo_upstreams.reset()

    through = []
    # The calls include send_email and transfer, which are high risk: an operator makes them.
    async with mcp_client(keystone_app, user="olivia") as client:
        for upstream, tool, arguments in CALLS:
            result = await client.call_tool(f"{upstream}__{tool}", arguments)
            through.append((result.is_error, blocks(result)))
    gateway_state = {name: demo_upstreams.state(name) for name in ("mail", "bank", "files")}

    assert len(direct) == len(through) == 8
    for (upstream, tool, _), seen, expected in zip(CALLS, through, direct, strict=True):
        assert seen == expected, f"{upstream}__{tool} differs through Keystone"
    # The effects on the upstreams are the same too, including the tools they were asked to run.
    assert gateway_state == direct_state
    assert len(keystone_app.audit.records) == 8


@pytest.mark.services
@pytest.mark.phase(1)
async def test_the_comparison_can_fail(
    keystone_app: KeystoneApp, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    # A guard against a comparison that always passes: different calls must look different.
    async with Client(demo_upstreams.url("bank")) as client:
        direct = blocks(await client.call_tool("get_balance", {"account": "SAV-002"}))
    async with mcp_client(keystone_app) as client:
        other = blocks(await client.call_tool("bank__get_balance", {"account": "CHK-001"}))

    assert direct != other
