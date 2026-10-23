"""KS-505 through the running gateway: GET /metrics after real calls."""

from typing import Any

import httpx2
import pytest
from prometheus_client.parser import text_string_to_metric_families

from tests.fixtures.keystone import KeystoneApp, McpConnect

pytestmark = [pytest.mark.phase(5), pytest.mark.services]


def scrape(
    app: KeystoneApp,
) -> tuple[httpx2.Response, dict[tuple[str, tuple[tuple[str, str], ...]], float]]:
    response = httpx2.get(f"{app.base}/metrics", timeout=10)
    found: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
    for family in text_string_to_metric_families(response.text):
        for sample in family.samples:
            found[(sample.name, tuple(sorted(sample.labels.items())))] = sample.value
    return response, found


def value(found: dict[Any, float], name: str, **labels: str) -> float:
    return found.get((name, tuple(sorted(labels.items()))), 0.0)


async def test_metrics_endpoint_exposes_counters(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    async with mcp_client(keystone_app) as client:
        await client.call_tool("echo__echo", {"payload": "a"})

    response, found = scrape(keystone_app)  # no token: Prometheus sends none

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain; version=")
    names = {name for name, _ in found}
    assert {
        "keystone_tool_calls_total",
        "keystone_tool_call_duration_seconds_bucket",
        "keystone_policy_eval_seconds_count",
        "keystone_audit_queue_depth",
    } <= names
    # The metrics of later phases are declared and have no samples yet.
    assert "# TYPE keystone_approvals_pending gauge" in response.text
    assert not any(name.startswith("keystone_approvals_pending") for name in names)


async def test_call_increments_counter_with_labels(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    async with mcp_client(keystone_app) as client:  # alice, of acme
        await client.call_tool("echo__echo", {"payload": "a"})
        await client.call_tool("echo__echo", {"payload": "b"})
        await client.call_tool(
            "bank__transfer", {"from_account": "CHK-001", "to": "SAV-002", "amount": 5}
        )  # denied by policy
        await client.call_tool("echo__made-up-one", {})
        await client.call_tool("echo__made-up-two", {})
        await client.call_tool("echo__echo", {"payload": 7})  # arguments that do not fit

    _, found = scrape(keystone_app)

    base = {"tenant": "acme", "tool": "echo__echo"}
    assert value(found, "keystone_tool_calls_total", **base, effect="allow", outcome="ok") == 2
    assert (
        value(
            found,
            "keystone_tool_calls_total",
            tenant="acme",
            tool="bank__transfer",
            effect="deny",
            outcome="rejected",
        )
        == 1
    )
    # Two tools that do not exist are one series, and the names the caller made up are not in it.
    unknown = {"tenant": "acme", "tool": "unknown", "effect": "none", "outcome": "rejected"}
    assert value(found, "keystone_tool_calls_total", **unknown) == 2
    assert value(found, "keystone_rejections_total", tenant="acme", code="KS_TOOL_NOT_FOUND") == 2
    assert value(found, "keystone_rejections_total", tenant="acme", code="KS_DENIED") == 1
    assert (
        value(found, "keystone_rejections_total", tenant="acme", code="KS_INVALID_ARGUMENTS") == 1
    )
    assert value(found, "keystone_tool_call_duration_seconds_count", stage="total") == 6
    assert value(found, "keystone_tool_call_duration_seconds_count", stage="upstream") == 2
    assert value(found, "keystone_tool_call_duration_seconds_count", stage="policy") >= 3
    # Two policy decisions for the listing are not made here; every call is decided once.
    assert value(found, "keystone_policy_eval_seconds_count") >= 3
    text = httpx2.get(f"{keystone_app.base}/metrics", timeout=10).text
    for private in ("made-up", "alice", "olivia"):
        assert private not in text, private
    assert value(found, "keystone_audit_failures_total", reason="flush_failed") == 0


async def test_the_quarantined_tools_gauge_follows_the_registry(
    keystone_app: KeystoneApp, mcp_client: McpConnect
) -> None:
    async with mcp_client(keystone_app) as client:
        await client.list_tools()

    _, found = scrape(keystone_app)

    assert value(found, "keystone_quarantined_tools", tenant="acme") == 0
    assert ("keystone_quarantined_tools", (("tenant", "acme"),)) in found
