"""KS-902: the parts of the red-team runner that need no gateway.

Whether the runner is right about a gateway it has run against is the integration test's job
(tests/integration/test_redteam_runner.py). What is fixed here is what it refuses to start against,
how it picks scenarios, and what the first line of a result file says.
"""

from typing import Any

import pytest

from eval.redteam.runner import (
    EXPECTED,
    GATEWAY_INFO,
    RULE_OF_TWO,
    ConfigMismatch,
    NaiveAgent,
    check_config,
    pick,
    start_line,
)
from eval.redteam.suite import load_scenarios

pytestmark = pytest.mark.phase(9)

BASE_POLICIES = [
    "approve-transfer-over-500",
    "external-email-needs-approval",
    "same-tenant-low-medium",
]


def facts(profile: str, scanner: str, *policies: str) -> dict[str, Any]:
    return {
        "profile": profile,
        "scanner": scanner,
        "policies": sorted(policies),
        "policy_version": 3,
    }


def test_each_label_names_the_profile_the_scanner_and_the_policies_it_needs() -> None:
    assert EXPECTED["C0"] == ("passthrough", "off", None)
    assert EXPECTED["C1"] == ("full", "off", False)
    assert EXPECTED["C2"] == ("full", "on", True)
    expected = {"rule-of-two", "tainted-external-effect", "deny-critical-when-tainted"}
    assert set(RULE_OF_TWO) == expected


def test_a_gateway_set_as_the_label_says_is_accepted() -> None:
    check_config("C0", facts("passthrough", "off", *BASE_POLICIES))
    check_config("C1", facts("full", "off", *BASE_POLICIES))
    check_config("C2", facts("full", "on", *BASE_POLICIES, *RULE_OF_TWO))


def test_the_policies_are_not_looked_at_for_the_passthrough() -> None:
    # In C0 the pipeline is stubbed, so the policies that are loaded do not matter.
    check_config("C0", facts("passthrough", "off"))
    check_config("C0", facts("passthrough", "off", *RULE_OF_TWO))


@pytest.mark.parametrize(
    ("config", "found", "said"),
    [
        ("C2", facts("passthrough", "off", *RULE_OF_TWO), "its profile is passthrough, not full"),
        ("C2", facts("full", "off", *RULE_OF_TWO), "its scanner is off, not on"),
        ("C2", facts("full", "on", *BASE_POLICIES), "the policies of the Rule of Two are not in"),
        ("C1", facts("full", "on", *BASE_POLICIES), "its scanner is on, not off"),
        ("C1", facts("full", "off", *RULE_OF_TWO), "the policies of the Rule of Two are in force"),
        ("C0", facts("full", "on", *RULE_OF_TWO), "its profile is full, not passthrough"),
    ],
)
def test_a_gateway_that_is_not_as_the_label_says_is_refused(
    config: Any, found: dict[str, Any], said: str
) -> None:
    with pytest.raises(ConfigMismatch, match=f"this is not {config}: .*{said}"):
        check_config(config, found)


def test_one_missing_rule_of_two_policy_is_a_gateway_without_the_rule_of_two() -> None:
    two_of_three = sorted(RULE_OF_TWO)[:2]

    with pytest.raises(ConfigMismatch, match="not in force"):
        check_config("C2", facts("full", "on", *BASE_POLICIES, *two_of_three))


def test_the_info_line_of_the_metrics_page_is_read() -> None:
    page = (
        "# HELP keystone_gateway_info How this gateway is set.\n"
        "# TYPE keystone_gateway_info gauge\n"
        'keystone_gateway_info{profile="passthrough",scanner="off"} 1.0\n'
        'keystone_calls_total{tool="x"} 4.0\n'
    )

    found = GATEWAY_INFO.search(page)

    assert found is not None and found["profile"] == "passthrough" and found["scanner"] == "off"
    assert GATEWAY_INFO.search("keystone_calls_total 4.0\n") is None


def test_scenarios_are_picked_by_id_with_a_wildcard_and_a_limit() -> None:
    scenarios = load_scenarios()

    assert len(pick(scenarios, [], None)) == 60
    assert [s.id for s in pick(scenarios, ["mail_invoice.exfil_email"], None)] == [
        "mail_invoice.exfil_email"
    ]
    assert len(pick(scenarios, ["*.benign"], None)) == 12
    assert len(pick(scenarios, ["web_*"], None)) == 15
    assert [s.id for s in pick(scenarios, ["mail_invoice.*", "*.benign"], 3)] == [
        "bank_balance.benign",
        "bank_history.benign",
        "bank_pay.benign",
    ]
    assert pick(scenarios, ["nothing.here"], None) == []


def test_a_wildcard_is_not_a_regular_expression() -> None:
    scenarios = load_scenarios()

    assert pick(scenarios, ["mail_invoice.exfil_email|web_vpn.benign"], None) == []
    assert pick(scenarios, [".*"], None) == []


def test_the_first_line_of_a_file_says_what_was_run_against() -> None:
    line = start_line(
        "C2",
        NaiveAgent(),
        1,
        facts("full", "on", *RULE_OF_TWO),
        scenarios=60,
        subset=False,
        variant=None,
        note="the matrix",
    )

    assert line["type"] == "start"
    assert (line["config"], line["agent"], line["model"], line["seeds"]) == ("C2", "naive", None, 1)
    assert (line["scenarios"], line["subset"], line["variant"]) == (60, False, None)
    assert line["gateway"]["profile"] == "full" and line["note"] == "the matrix"
    assert len(line["commit"]) == 40 and isinstance(line["dirty"], bool)
    assert set(line["machine"]) == {"platform", "python", "cpus"}
