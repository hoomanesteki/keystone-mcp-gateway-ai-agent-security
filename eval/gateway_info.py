"""Read what a running Keystone says of itself at `/metrics`, for the tools that measure it.

The red-team runner (KS-902) and the performance harness (KS-903) both have to know which gateway
they are measuring before they publish a number about it: its profile, whether it scans, with what
model, and whether that model has loaded. They also read the time a call spends in each stage of
the pipeline, which is how the harness says where the time goes.
"""

from __future__ import annotations

from collections.abc import Mapping

from prometheus_client.parser import text_string_to_metric_families

STAGE_HISTOGRAM = "keystone_tool_call_duration_seconds"


def read_info(page: str) -> tuple[dict[str, str] | None, dict[str, bool]]:
    """How a gateway says it is set, from its `/metrics` page: the labels of
    `keystone_gateway_info` (profile, scanner, classifier), and for each model whether
    `keystone_scanner_classifier_ready` says it has loaded. The labels come in the order the
    client library sorts them, so they are read as labels and not matched as text."""
    info: dict[str, str] | None = None
    ready: dict[str, bool] = {}
    for family in text_string_to_metric_families(page):
        for sample in family.samples:
            if sample.name == "keystone_gateway_info" and sample.value == 1:
                info = dict(sample.labels)
            elif sample.name == "keystone_scanner_classifier_ready":
                ready[sample.labels["classifier"]] = sample.value == 1
    if info is not None and not {"profile", "scanner", "classifier"} <= info.keys():
        return None, ready
    return info, ready


def stage_totals(page: str) -> dict[str, tuple[float, float]]:
    """For each stage of `keystone_tool_call_duration_seconds` (`total`, `upstream`, and the name
    of each interceptor), the seconds spent in it and the number of times, since the gateway
    started."""
    sums: dict[str, float] = {}
    counts: dict[str, float] = {}
    for family in text_string_to_metric_families(page):
        for sample in family.samples:
            if "stage" not in sample.labels:
                continue
            if sample.name == f"{STAGE_HISTOGRAM}_sum":
                sums[sample.labels["stage"]] = sample.value
            elif sample.name == f"{STAGE_HISTOGRAM}_count":
                counts[sample.labels["stage"]] = sample.value
    return {stage: (sums.get(stage, 0.0), counts[stage]) for stage in counts}


def stage_means_ms(
    before: Mapping[str, tuple[float, float]], after: Mapping[str, tuple[float, float]]
) -> dict[str, dict[str, float]]:
    """The mean time in each stage over the calls made between two reads of `stage_totals`, in
    milliseconds, with how many calls it was a mean of. A stage that saw no call between them is
    left out."""
    means: dict[str, dict[str, float]] = {}
    for stage, (seconds, calls) in after.items():
        was_seconds, was_calls = before.get(stage, (0.0, 0.0))
        made = calls - was_calls
        if made > 0:
            means[stage] = {
                "mean_ms": (seconds - was_seconds) / made * 1000,
                "calls": made,
            }
    return means
