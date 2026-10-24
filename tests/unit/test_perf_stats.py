"""KS-903: the numbers of the performance harness, on lists small enough to count by hand."""

import pytest

from eval.perf.load import PARAGRAPH, Spec, payload
from eval.perf.stats import overhead, summarize
from keystone.defense.rules import analyze, default_rules

pytestmark = pytest.mark.phase(9)


def test_percentiles() -> None:
    # 1 to 100 milliseconds, one call each. By the nearest-rank rule the 50th percentile is the
    # 50th fastest call, the 95th the 95th, and the 99th the 99th.
    latencies = [float(n) for n in range(100, 0, -1)]  # in no order

    summary = summarize(latencies, wall_s=2.0)

    assert (summary["p50_ms"], summary["p95_ms"], summary["p99_ms"]) == (50.0, 95.0, 99.0)
    assert (summary["mean_ms"], summary["max_ms"]) == (50.5, 100.0)
    assert summary["calls"] == 100 and summary["throughput"] == 50.0
    # 20 timings: the 95th is the 19th of the sorted list, as the detector's table counts it.
    twenty = [float(n) for n in range(1, 21)]
    assert summarize(twenty, wall_s=1.0)["p95_ms"] == 19.0
    # One call is every percentile.
    one = summarize([7.5], wall_s=0.01)
    assert (one["p50_ms"], one["p95_ms"], one["p99_ms"]) == (7.5, 7.5, 7.5)


def test_errors_are_counted_as_a_share_of_the_calls_and_left_out_of_the_percentiles() -> None:
    # Four calls succeeded and one failed. The percentiles are of the four, so a refusal that came
    # back quickly does not make the gateway look faster the more it fails.
    summary = summarize([1.0, 2.0, 3.0, 4.0], wall_s=1.0, errors=1)

    assert summary["calls"] == 5 and summary["errors"] == 1 and summary["error_rate"] == 0.2
    assert summary["p50_ms"] == 2.0 and summary["throughput"] == 4.0


def test_a_run_in_which_nothing_succeeded_has_no_percentiles_and_no_throughput() -> None:
    summary = summarize([], wall_s=2.0, errors=10)

    assert summary["calls"] == 10 and summary["error_rate"] == 1.0
    assert (summary["p50_ms"], summary["p95_ms"], summary["mean_ms"], summary["max_ms"]) == (
        None,
        None,
        None,
        None,
    )
    assert summary["throughput"] == 0.0


@pytest.mark.parametrize(
    ("latencies", "wall", "errors", "message"),
    [
        ([], 1.0, 0, "no calls"),
        ([1.0], 0.0, 0, "no time"),
        ([1.0], 1.0, -1, "negative"),
    ],
)
def test_a_summary_that_would_mean_nothing_is_refused(
    latencies: list[float], wall: float, errors: int, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        summarize(latencies, wall, errors)


def test_the_overhead_is_the_difference_at_each_percentile() -> None:
    direct = summarize([float(n) for n in range(1, 101)], wall_s=1.0)
    through = summarize([float(n) * 3 + 5 for n in range(1, 101)], wall_s=1.0)

    assert overhead(through, direct) == {"p50_ms": 105.0, "p95_ms": 195.0, "p99_ms": 203.0}
    # Where the two lists overlap it can be negative: it is the difference of two percentiles.
    assert overhead(direct, through)["p50_ms"] == -105.0
    # A run in which nothing succeeded adds nothing that can be said.
    nothing = summarize([], wall_s=1.0, errors=5)
    assert overhead(nothing, direct) == {"p50_ms": None, "p95_ms": None, "p99_ms": None}


@pytest.mark.parametrize("size", [1, 100, 1024, 8192, 100_000])
def test_the_payload_is_the_size_asked_for_and_plain_ascii(size: int) -> None:
    text = payload(size)

    assert len(text) == size and len(text.encode("utf-8")) == size
    assert text == (PARAGRAPH * (size // len(PARAGRAPH) + 1))[:size]


def test_the_payload_holds_nothing_the_scanner_would_flag() -> None:
    # A payload that tripped a rule would measure the cost of acting on a flag, and not of reading
    # a harmless output.
    for size in (1024, 8192):
        assert analyze(payload(size), default_rules()).hits == []


def test_a_payload_of_no_bytes_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one byte"):
        payload(0)


def test_a_share_of_the_sessions_keeps_everything_else_of_the_run() -> None:
    spec = Spec("http://x/mcp", "echo", {"X-Api-Key": "k"}, 200, 20, 1024, user="olivia")

    share = spec.share(50)

    assert (share.sessions, share.calls, share.size, share.user) == (50, 20, 1024, "olivia")
    assert share.headers == spec.headers and spec.sessions == 200


async def test_the_token_of_the_open_sessions_can_be_replaced_while_they_run() -> None:
    import httpx2

    from eval.perf.load import Bearer

    seen: list[str | None] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers.get("authorization"))
        return httpx2.Response(200)

    bearer = Bearer("first")
    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler), auth=bearer, base_url="http://x"
    ) as client:
        await client.get("/a")
        bearer.token = "second"
        await client.get("/b")

    assert seen == ["Bearer first", "Bearer second"]


def test_a_failed_call_is_counted_by_the_code_and_the_start_of_the_message() -> None:
    import mcp_types as types

    from eval.perf.load import error_kind

    def failed(text: str) -> types.CallToolResult:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)], is_error=True
        )

    refused = failed("[keystone:KS_DENIED] session state is unavailable. Call id 01ABC.")
    assert (
        error_kind(refused) == "tool error KS_DENIED: session state is unavailable. Call id 01ABC."
    )
    # A message that varies is cut at 60 characters, so that the kinds stay few.
    long = failed("[keystone:KS_UPSTREAM_ERROR] " + "x" * 200)
    assert error_kind(long) == "tool error KS_UPSTREAM_ERROR: " + "x" * 60
    # The id of the call differs in every message and is not part of the kind.
    ided = failed("[keystone:KS_DENIED] call 01M5PT8AN0MV4DCC6M2Y9DNKNK denied: no decision")
    assert error_kind(ided) == "tool error KS_DENIED: denied: no decision"
    # An error that Keystone did not write is still counted, by what it said.
    assert error_kind(failed("the upstream broke")) == "tool error: the upstream broke"
    assert error_kind(types.CallToolResult(content=[], is_error=True)) == "tool error"
