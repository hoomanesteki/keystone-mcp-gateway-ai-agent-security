"""KS-704: what the scanning slots write in the metrics.

`keystone_scan_score` takes one score for each output that was scanned, and
`keystone_sessions_tainted_total` counts the sessions an injection tainted. Both are labelled by
tenant only, and a tenant that is not in the config shares the series `other`, as for every metric
(KS-505).
"""

import pytest

from keystone.telemetry.metrics import Metrics
from tests.fixtures.scan import sample, tainted_sessions

pytestmark = pytest.mark.phase(7)


def bucket(metrics: Metrics, tenant: str, upto: str) -> float:
    return sample(metrics, "keystone_scan_score_bucket", {"tenant": tenant, "le": upto})


def test_a_score_lands_in_the_histogram_of_its_tenant() -> None:
    metrics = Metrics(tenants=["acme", "globex"])

    metrics.scan_scored("acme", 0.0)
    metrics.scan_scored("acme", 0.88)
    metrics.scan_scored("globex", 0.55)

    assert sample(metrics, "keystone_scan_score_count", {"tenant": "acme"}) == 2
    assert sample(metrics, "keystone_scan_score_sum", {"tenant": "acme"}) == pytest.approx(0.88)
    # 0.88 is above 0.8 and not above 0.9, which is the bucket the dashboard reads the demo from.
    assert (bucket(metrics, "acme", "0.1"), bucket(metrics, "acme", "0.8")) == (1, 1)
    assert (bucket(metrics, "acme", "0.9"), bucket(metrics, "acme", "1.0")) == (2, 2)
    assert sample(metrics, "keystone_scan_score_count", {"tenant": "globex"}) == 1


def test_a_tenant_that_is_not_configured_shares_one_series() -> None:
    metrics = Metrics(tenants=["acme"])

    metrics.scan_scored("made-up-1", 0.5)
    metrics.scan_scored("made-up-2", 0.5)
    metrics.session_tainted("made-up-3")

    assert sample(metrics, "keystone_scan_score_count", {"tenant": "other"}) == 2
    assert tainted_sessions(metrics, "other") == 1
    assert sample(metrics, "keystone_scan_score_count", {"tenant": "made-up-1"}) == 0


def test_tainted_sessions_are_counted_by_tenant() -> None:
    metrics = Metrics(tenants=["acme", "globex"])

    metrics.session_tainted("acme")
    metrics.session_tainted("acme")
    metrics.session_tainted("globex")

    assert (tainted_sessions(metrics, "acme"), tainted_sessions(metrics, "globex")) == (2, 1)


def test_the_metrics_are_declared_with_the_tenant_as_their_only_label() -> None:
    declared = {metric.name: metric for metric in Metrics().declared}

    assert declared["keystone_scan_score"].kind == "histogram"
    assert declared["keystone_scan_score"].labels == ("tenant",)
    assert declared["keystone_sessions_tainted_total"].labels == ("tenant",)


def test_what_the_model_did_is_counted_for_each_scan() -> None:
    """KS-992: the share of scans the model answered, and why the others went without it."""
    metrics = Metrics(tenants=["acme"])

    for model in ("protectai-deberta-v2", "protectai-deberta-v2", "busy", "timeout", "skipped"):
        metrics.scan_modelled(model)
    metrics.scan_modelled(None)

    def counted(kind: str) -> float:
        return sample(metrics, "keystone_scan_model_total", {"model": kind})

    assert [counted(k) for k in ("answered", "busy", "timeout", "skipped", "error", "none")] == [
        2,
        1,
        1,
        1,
        0,
        1,
    ]
