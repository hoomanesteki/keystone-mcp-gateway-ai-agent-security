"""KS-506: the Grafana dashboard asks for metrics that exist, and Prometheus scrapes Keystone."""

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from keystone.telemetry.metrics import Metrics

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "deploy" / "grafana" / "dashboards" / "keystone.json"
PROVISIONING = ROOT / "deploy" / "grafana" / "provisioning"
METRIC_NAME = re.compile(r"\bkeystone_[a-z0-9_]+")
GROUP_BY = re.compile(r"\bby\s*\(([^)]*)\)")
MATCHER = re.compile(r"[{,]\s*([a-z_]+)\s*(?:=~|!=|=)")
HISTOGRAM_SUFFIXES = ("_bucket", "_sum", "_count")

ROWS = ["Traffic", "Latency", "Upstreams", "Audit", "Approvals, scanner and budget"]
LATER_PHASES = [
    "keystone_approvals_pending",
    "keystone_sessions_tainted_total",
    "keystone_scan_score",
    "keystone_rate_limited_total",
    "keystone_budget_spent_usd",
    "keystone_llm_tokens_total",
]


def dashboard() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(DASHBOARD.read_text())
    return loaded


def panels(board: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for panel in board["panels"]:
        found.append(panel)
        found.extend(panel.get("panels", []))
    return found


def expressions(board: dict[str, Any]) -> list[str]:
    return [t["expr"] for p in panels(board) for t in p.get("targets", [])]


def known_names() -> set[str]:
    names = set()
    for metric in Metrics().declared:
        names.add(metric.name)
        if metric.kind == "histogram":
            names |= {metric.name + suffix for suffix in HISTOGRAM_SUFFIXES}
    return names


def metric_of(name: str) -> str:
    """The metric a queried series belongs to: a histogram is queried as _bucket, _sum or _count."""
    for suffix in HISTOGRAM_SUFFIXES:
        histograms = {m.name for m in Metrics().declared if m.kind == "histogram"}
        if name.endswith(suffix) and name.removesuffix(suffix) in histograms:
            return name.removesuffix(suffix)
    return name


def unknown_metrics(board: dict[str, Any]) -> set[str]:
    used = {name for expr in expressions(board) for name in METRIC_NAME.findall(expr)}
    return used - known_names()


@pytest.mark.phase(5)
def test_the_dashboard_check_can_fail() -> None:
    board = dashboard()
    first = next(p for p in panels(board) if p.get("targets"))
    first["targets"][0]["expr"] = "sum(rate(keystone_tool_calls_totl[1m]))"

    assert unknown_metrics(board) == {"keystone_tool_calls_totl"}


@pytest.mark.phase(5)
def test_dashboard_queries_reference_known_metrics() -> None:
    board = dashboard()

    used = {name for expr in expressions(board) for name in METRIC_NAME.findall(expr)}

    assert used, "the dashboard asks for no metric"
    assert unknown_metrics(board) == set()
    # The panels of Phases 6 to 8 are there from the start, on metrics that are declared and empty.
    assert set(LATER_PHASES) <= {metric_of(name) for name in used}


@pytest.mark.phase(5)
def test_dashboard_groups_and_filters_only_by_labels_that_exist() -> None:
    labels = {label for metric in Metrics().declared for label in metric.labels} | {"le"}

    for expr in expressions(dashboard()):
        grouped = {part.strip() for group in GROUP_BY.findall(expr) for part in group.split(",")}
        assert grouped <= labels, (expr, grouped - labels)
        assert set(MATCHER.findall(expr)) <= labels, (expr, set(MATCHER.findall(expr)) - labels)


@pytest.mark.phase(5)
def test_dashboard_has_the_planned_rows_and_sound_panels() -> None:
    board = dashboard()
    shown = panels(board)

    assert [p["title"] for p in shown if p["type"] == "row"] == ROWS
    ids = [p["id"] for p in shown]
    assert len(ids) == len(set(ids))
    for panel in shown:
        if panel["type"] == "row":
            continue
        assert panel["targets"], panel["title"]
        assert panel["datasource"] == {"type": "prometheus", "uid": "prometheus"}
        for target in panel["targets"]:
            assert target["datasource"] == panel["datasource"]
            assert target["expr"].strip()
    assert board["uid"] == "keystone-overview" and board["title"] == "Keystone"


@pytest.mark.phase(5)
def test_the_datasource_uid_is_provisioned_and_the_dashboard_folder_is_mounted() -> None:
    sources = yaml.safe_load((PROVISIONING / "datasources" / "datasources.yml").read_text())
    assert "prometheus" in {s["uid"] for s in sources["datasources"]}

    provider = yaml.safe_load((PROVISIONING / "dashboards" / "dashboards.yml").read_text())
    path = provider["providers"][0]["options"]["path"]
    compose = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text())
    mounts = compose["services"]["grafana"]["volumes"]
    assert f"./grafana/dashboards:{path}:ro" in mounts


@pytest.mark.phase(5)
def test_prometheus_scrapes_keystone() -> None:
    config = yaml.safe_load((ROOT / "deploy" / "prometheus" / "prometheus.yml").read_text())

    [job] = [j for j in config["scrape_configs"] if j["job_name"] == "keystone"]

    assert job["metrics_path"] == "/metrics"
    assert job["static_configs"][0]["targets"] == ["keystone:8080"]
