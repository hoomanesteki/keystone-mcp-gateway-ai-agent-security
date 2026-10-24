"""KS-902 and KS-903: reading what a gateway says of itself at /metrics."""

import pytest

from eval.gateway_info import read_info, stage_means_ms, stage_totals

pytestmark = pytest.mark.phase(9)

MODEL = "protectai-deberta-v2"


def test_the_info_is_read_as_labels_in_any_order() -> None:
    page = (
        "# HELP keystone_gateway_info How this gateway is set.\n"
        "# TYPE keystone_gateway_info gauge\n"
        'keystone_gateway_info{classifier="none",profile="passthrough",scanner="off"} 1.0\n'
        "# TYPE keystone_scanner_classifier_ready gauge\n"
        f'keystone_scanner_classifier_ready{{classifier="{MODEL}"}} 1.0\n'
        'keystone_calls_total{tool="x"} 4.0\n'
    )

    info, ready = read_info(page)

    assert info == {"classifier": "none", "profile": "passthrough", "scanner": "off"}
    assert ready == {MODEL: True}
    shuffled = 'keystone_gateway_info{scanner="on",profile="full",classifier="x"} 1.0\n'
    assert read_info(shuffled)[0] == {"classifier": "x", "profile": "full", "scanner": "on"}


def test_a_page_without_the_info_or_with_part_of_it_says_nothing() -> None:
    assert read_info("keystone_calls_total 4.0\n") == (None, {})
    older = 'keystone_gateway_info{profile="full",scanner="on"} 1.0\n'
    assert read_info(older) == (None, {})
    not_one = 'keystone_gateway_info{classifier="none",profile="full",scanner="on"} 0.0\n'
    assert read_info(not_one) == (None, {})
    loading = read_info(f'keystone_scanner_classifier_ready{{classifier="{MODEL}"}} 0.0\n')
    assert loading[1] == {MODEL: False}


def histogram(stage: str, total: float, count: int) -> str:
    name = "keystone_tool_call_duration_seconds"
    return (
        f'{name}_bucket{{le="+Inf",stage="{stage}"}} {count}.0\n'
        f'{name}_count{{stage="{stage}"}} {count}.0\n'
        f'{name}_sum{{stage="{stage}"}} {total}\n'
    )


PAGE = (
    "# TYPE keystone_tool_call_duration_seconds histogram\n"
    + histogram("total", 6.0, 100)
    + histogram("upstream", 2.0, 100)
    + histogram("policy", 0.5, 100)
)


def test_the_time_in_each_stage_is_read_from_the_histogram() -> None:
    assert stage_totals(PAGE) == {
        "total": (6.0, 100.0),
        "upstream": (2.0, 100.0),
        "policy": (0.5, 100.0),
    }
    assert stage_totals("keystone_calls_total 1.0\n") == {}


def test_the_mean_over_a_run_is_the_difference_of_two_reads() -> None:
    before = stage_totals(PAGE)
    after = stage_totals(
        "# TYPE keystone_tool_call_duration_seconds histogram\n"
        + histogram("total", 9.0, 200)
        + histogram("upstream", 2.5, 200)
        + histogram("policy", 0.5, 100)  # no call went through this one
        + histogram("metering", 0.2, 50)  # new since the first read
    )

    means = stage_means_ms(before, after)

    # 3 seconds over 100 more calls is 30 ms a call; the stage that saw no call is left out.
    assert means["total"] == {"mean_ms": pytest.approx(30.0), "calls": 100}
    assert means["upstream"]["mean_ms"] == pytest.approx(5.0)
    assert "policy" not in means
    assert means["metering"] == {"mean_ms": pytest.approx(4.0), "calls": 50}
