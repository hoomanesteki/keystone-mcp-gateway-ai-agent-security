"""KS-703: benign output passes byte for byte.

The eight calls of the Phase 1 equivalence test run against the demo upstreams, and the scanner
guard looks at each result. None of them may be touched, so that when the guard is in the pipeline
(KS-704) `test_direct_vs_gateway_identical` still holds. The seeded mail, files and balances are
ordinary text, and a scanner that flagged them would break that test, or worse, change what an
agent reads.
"""

from typing import Any

import pytest
from mcp import Client

from keystone.core.types import Risk, ToolResult
from keystone.defense.scanner import build_scanner_guard
from keystone.settings import ScannerSettings
from tests.fixtures.calls import make_tool
from tests.fixtures.upstreams import DemoUpstreams
from tests.integration.test_equivalence import CALLS

pytestmark = pytest.mark.phase(7)


def as_tool_result(result: Any) -> ToolResult:
    return ToolResult(
        content=[
            b.model_dump(by_alias=True, mode="json", exclude_none=True) for b in result.content
        ],
        structured_content=result.structured_content,
        is_error=result.is_error,
    )


@pytest.mark.parametrize("risk", [Risk.LOW, Risk.HIGH, Risk.CRITICAL])
async def test_the_results_of_the_equivalence_calls_pass_unchanged(
    demo_upstreams: DemoUpstreams, risk: Risk
) -> None:
    guard = build_scanner_guard(ScannerSettings(classifier="none"))

    for upstream, tool, arguments in CALLS:
        async with Client(demo_upstreams.url(upstream)) as client:
            result = as_tool_result(await client.call_tool(tool, arguments))
        before = result.model_dump_json()

        seen = await guard.inspect(result, make_tool(upstream, tool, risk=risk), "01JEQUIV")

        assert seen.result is result, f"{upstream}__{tool}"
        assert result.model_dump_json() == before
        assert seen.scan.label == "benign" and seen.scan.action == "pass", f"{upstream}__{tool}"


async def test_every_seeded_email_and_file_is_benign(demo_upstreams: DemoUpstreams) -> None:
    guard = build_scanner_guard(ScannerSettings(classifier="none"))
    reads = [("mail", "read_email", {"email_id": f"m{n:02d}"}) for n in range(1, 13)]
    reads += [
        ("files", "read_file", {"path": path})
        for path in (
            "README.txt",
            "notes/meeting-2026-10-02.md",
            "notes/offsite-venues.md",
            "reports/customer-call-recap.txt",
            "reports/q3-summary.csv",
        )
    ]
    flagged = []

    for upstream, tool, arguments in reads:
        async with Client(demo_upstreams.url(upstream)) as client:
            result = as_tool_result(await client.call_tool(tool, arguments))
        seen = await guard.inspect(result, make_tool(upstream, tool), "01JEQUIV")
        if seen.result is not result:
            flagged.append((upstream, tool, arguments))

    assert flagged == []
