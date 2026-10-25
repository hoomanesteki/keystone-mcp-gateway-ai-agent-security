"""KS-903: the load harness against a real gateway and a real echo upstream, in a small run.

10 sessions make 5 calls each, once straight at the echo server and once through Keystone, as the
nightly job does against the compose stack. What is fixed here is that the harness opens its
sessions, times every call, counts none as failed, and that the counters the gateway keeps for the
stages of a call are the ones it reads.
"""

import httpx
import pytest

from eval.gateway_info import stage_means_ms, stage_totals
from eval.perf.load import Spec, run_load
from eval.perf.stats import summarize
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(9), pytest.mark.services]

SESSIONS = 10
CALLS = 5


def through(app: KeystoneApp, idp: FakeIdp, size: int = 1024) -> Spec:
    token = idp.token_for("olivia")
    headers = {"Authorization": f"Bearer {token}"}
    return Spec(app.url, "echo__echo", headers, SESSIONS, CALLS, size)


async def test_load_smoke_runs(
    keystone_app: KeystoneApp, fake_idp: FakeIdp, demo_upstreams: DemoUpstreams
) -> None:
    direct = Spec(demo_upstreams.url("echo"), "echo", {}, SESSIONS, CALLS, 1024)

    alone = await run_load(direct, processes=1)
    gateway = await run_load(through(keystone_app, fake_idp), processes=1)

    for result in (alone, gateway):
        summary = result["summary"]
        assert result["opened"] == SESSIONS and result["errors"] == {}
        assert summary["calls"] == SESSIONS * CALLS and summary["errors"] == 0
        assert 0 < summary["p50_ms"] <= summary["p95_ms"] <= summary["p99_ms"] <= summary["max_ms"]
        assert summary["throughput"] > 0 and len(result["latencies_ms"]) == SESSIONS * CALLS
        assert result["stopped_early"] is False
    # The gateway does more than the upstream alone, so a call through it is not faster.
    assert gateway["summary"]["p50_ms"] > alone["summary"]["p50_ms"]
    # The summary can be made again from the latencies, which is how the report does it.
    again = summarize(gateway["latencies_ms"], gateway["summary"]["wall_s"])
    assert again["p95_ms"] == gateway["summary"]["p95_ms"]


async def test_the_sessions_can_be_shared_out_over_processes(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    result = await run_load(through(keystone_app, fake_idp), processes=2)

    assert result["opened"] == SESSIONS and result["errors"] == {}
    assert result["summary"]["calls"] == SESSIONS * CALLS
    # Two processes, five sessions each, and each said how busy it was.
    assert result["spec"]["processes"] == 2 and len(result["generator"]) == 2
    assert all(g["wall_s"] > 0 and g["cpu_s"] >= 0 for g in result["generator"])


async def test_the_time_in_each_stage_is_read_between_the_warm_up_and_the_end(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    seen: dict[str, dict[str, tuple[float, float]]] = {}

    async def before() -> None:
        async with httpx.AsyncClient(timeout=10) as http:
            seen["before"] = stage_totals((await http.get(f"{keystone_app.base}/metrics")).text)

    await run_load(through(keystone_app, fake_idp), processes=1, on_go=before)
    async with httpx.AsyncClient(timeout=10) as http:
        after = stage_totals((await http.get(f"{keystone_app.base}/metrics")).text)

    means = stage_means_ms(seen["before"], after)

    # The warm-up calls (3 for each session) were made before the first read, so the counters of
    # the stages count the timed calls and no more.
    assert means["total"]["calls"] == SESSIONS * CALLS
    assert (
        means["upstream"]["mean_ms"] > 0
        and means["total"]["mean_ms"] >= means["upstream"]["mean_ms"]
    )
    assert {"rate_limit", "policy", "credential", "output_scan"} <= set(means)


async def test_a_session_that_cannot_open_is_counted_and_does_not_hold_the_others(
    keystone_app: KeystoneApp,
) -> None:
    # No token: Keystone answers 401 and the sessions do not open. The run ends, and says so.
    spec = Spec(keystone_app.url, "echo__echo", {}, 3, 2, 1024)

    result = await run_load(spec, processes=1)

    assert result["opened"] == 0 and result["summary"] is None
    assert sum(result["errors"].values()) == 3
    assert all(kind.startswith("open: ") for kind in result["errors"])


async def test_calls_that_fail_are_counted_by_cause_and_kept_apart_from_the_ones_that_succeed(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    # A tool that does not exist: every call is refused by the gateway, and answered at once.
    spec = through(keystone_app, fake_idp)
    spec = Spec(spec.url, "echo__nothing", spec.headers, SESSIONS, CALLS, 1024)

    result = await run_load(spec, processes=1)

    summary = result["summary"]
    assert result["opened"] == SESSIONS
    # Fifty calls failed, none succeeded, and the percentiles say that nothing can be said of them.
    assert summary["calls"] == SESSIONS * CALLS and summary["errors"] == SESSIONS * CALLS
    assert summary["error_rate"] == 1.0 and summary["p50_ms"] is None
    assert result["latencies_ms"] == [] and len(result["failed_ms"]) == SESSIONS * CALLS
    [(kind, count)] = result["errors"].items()
    assert kind.startswith("tool error KS_TOOL_NOT_FOUND: ") and count == SESSIONS * CALLS
    # Where each failure was: which call of its session, and how long after the timed calls began.
    assert sorted(result["failed_calls"]) == sorted(list(range(1, CALLS + 1)) * SESSIONS)
    assert len(result["failed_at_s"]) == SESSIONS * CALLS and min(result["failed_at_s"]) >= 0
