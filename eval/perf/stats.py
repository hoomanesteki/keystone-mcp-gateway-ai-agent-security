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
    """The percentiles, the mean and the largest of the latencies, the calls a second over the
    time the calls took, and the share of calls that failed. `latencies_ms` holds every call,
    including the ones that failed (they were timed too); `errors` says how many of them failed."""
    if not latencies_ms:
        raise ValueError("there are no latencies to summarize")
    if wall_s <= 0:
        raise ValueError("the calls took no time")
    if not 0 <= errors <= len(latencies_ms):
        raise ValueError("there cannot be more errors than calls")
    calls = len(latencies_ms)
    return {
        "calls": calls,
        "errors": errors,
        "error_rate": errors / calls,
        **{f"p{q}_ms": percentile(latencies_ms, q) for q in PERCENTILES},
        "mean_ms": sum(latencies_ms) / calls,
        "max_ms": max(latencies_ms),
        "wall_s": wall_s,
        "throughput": calls / wall_s,
    }


def overhead(target: Mapping[str, Any], direct: Mapping[str, Any]) -> dict[str, float]:
    """What the gateway adds at each percentile: the latency through it minus the latency of the
    upstream alone, in milliseconds. The two are percentiles of two lists, and not the percentile
    of a difference, so it can be negative where the two lists overlap."""
    return {f"p{q}_ms": target[f"p{q}_ms"] - direct[f"p{q}_ms"] for q in PERCENTILES}
