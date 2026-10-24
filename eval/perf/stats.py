"""The numbers of the performance harness, in plain Python (KS-903).

A run is a list of latencies, one for each call, in milliseconds. These functions say what the list
means: the percentiles by the nearest-rank rule (the same `percentile` as the detector's latency
table: for 4,000 calls the 95th is the 3,800th fastest), how many calls failed, how many were made
a second, and how much a gateway adds to what the upstream does alone, at each percentile.

There are no dependencies, so the smoke run in CI needs none.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from eval.detector.metrics import percentile

PERCENTILES = (50, 95, 99)


def summarize(latencies_ms: Sequence[float], wall_s: float, errors: int = 0) -> dict[str, Any]:
    """The percentiles, the mean and the largest of the latencies of the calls that succeeded, the
    calls a second over the time the calls took, and the share of calls that failed.

    A call that failed is counted in `errors` and left out of the percentiles: a gateway that
    refuses a call quickly (it is out of connections, say) would otherwise look faster the more
    it failed. `calls` is every call that was made, `throughput` the ones that succeeded in each
    second. If no call succeeded the percentiles are None."""
    if errors < 0:
        raise ValueError("there cannot be a negative number of errors")
    calls = len(latencies_ms) + errors
    if calls == 0:
        raise ValueError("there are no calls to summarize")
    if wall_s <= 0:
        raise ValueError("the calls took no time")
    served = bool(latencies_ms)
    return {
        "calls": calls,
        "errors": errors,
        "error_rate": errors / calls,
        **{f"p{q}_ms": percentile(latencies_ms, q) if served else None for q in PERCENTILES},
        "mean_ms": sum(latencies_ms) / len(latencies_ms) if served else None,
        "max_ms": max(latencies_ms) if served else None,
        "wall_s": wall_s,
        "throughput": len(latencies_ms) / wall_s,
    }


def overhead(target: Mapping[str, Any], direct: Mapping[str, Any]) -> dict[str, float | None]:
    """What the gateway adds at each percentile: the latency through it minus the latency of the
    upstream alone, in milliseconds. The two are percentiles of two lists, and not the percentile
    of a difference, so it can be negative where the two lists overlap. None where either run had
    no call that succeeded."""
    if any(summary[f"p{q}_ms"] is None for summary in (target, direct) for q in PERCENTILES):
        return {f"p{q}_ms": None for q in PERCENTILES}
    return {f"p{q}_ms": target[f"p{q}_ms"] - direct[f"p{q}_ms"] for q in PERCENTILES}
