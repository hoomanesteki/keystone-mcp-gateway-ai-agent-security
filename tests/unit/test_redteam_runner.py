"""KS-902: the parts of the red-team runner that need no gateway.

Whether the runner is right about a gateway it has run against is the integration test's job
(tests/integration/test_redteam_runner.py). What is fixed here is what it refuses to start against,
how it picks scenarios, and what the first line of a result file says.
"""

from typing import Any

import httpx
import pytest

from eval.redteam import runner
from eval.redteam.runner import (
    EXPECTED,
    RULE_OF_TWO,
    ConfigMismatch,
    NaiveAgent,
    Target,
    Tokens,
    check_config,
    facts_with_the_model,
    gateway_facts,
    pick,
    read_info,
    start_line,
)
from eval.redteam.suite import load_scenarios
from eval.redteam.witness import Witness

pytestmark = pytest.mark.phase(9)

BASE_POLICIES = [
    "approve-transfer-over-500",
    "external-email-needs-approval",
    "same-tenant-low-medium",
]


MODEL = "protectai-deberta-v2"


def facts(
    profile: str,
    scanner: str,
    *policies: str,
    classifier: str | None = None,
    ready: bool | None = None,
) -> dict[str, Any]:
    """What a gateway says of itself. A gateway that scans has its model, loaded, unless the test
    says it has not."""
    if classifier is None:
        classifier = MODEL if scanner == "on" else "none"
    if ready is None and classifier != "none":
        ready = True
    return {
        "profile": profile,
        "scanner": scanner,
        "classifier": classifier,
        "classifier_ready": ready,
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
        (
            "C2",
            facts("full", "on", *RULE_OF_TWO, classifier="none"),
            "its scanner has no model, so it scores by the rules alone",
        ),
        (
            "C2",
            facts("full", "on", *RULE_OF_TWO, ready=False),
            f"its model {MODEL} has not loaded",
        ),
    ],
)
def test_a_gateway_that_is_not_as_the_label_says_is_refused(
    config: Any, found: dict[str, Any], said: str
) -> None:
    with pytest.raises(ConfigMismatch, match=f"this is not {config}: .*{said}"):
        check_config(config, found)


def test_a_scanner_on_the_rules_alone_is_accepted_only_where_the_caller_says_so() -> None:
    rules_only = facts("full", "on", *RULE_OF_TWO, classifier="none")

    check_config("C2", rules_only, model=False)
    with pytest.raises(ConfigMismatch, match="no model"):
        check_config("C2", rules_only)
    # C1 has no scanner, so a model is not asked of it.
    check_config("C1", facts("full", "off", *BASE_POLICIES))


def test_one_missing_rule_of_two_policy_is_a_gateway_without_the_rule_of_two() -> None:
    two_of_three = sorted(RULE_OF_TWO)[:2]

    with pytest.raises(ConfigMismatch, match="not in force"):
        check_config("C2", facts("full", "on", *BASE_POLICIES, *two_of_three))


def test_the_info_of_the_metrics_page_is_read_as_labels_in_any_order() -> None:
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
    # The same labels in another order are the same gateway.
    shuffled = 'keystone_gateway_info{scanner="on",profile="full",classifier="x"} 1.0\n'
    assert read_info(shuffled)[0] == {"classifier": "x", "profile": "full", "scanner": "on"}


def test_a_page_without_the_info_or_with_part_of_it_says_nothing() -> None:
    assert read_info("keystone_calls_total 4.0\n") == (None, {})
    # An older gateway that has no model label does not say how it is set.
    older = 'keystone_gateway_info{profile="full",scanner="on"} 1.0\n'
    assert read_info(older) == (None, {})
    not_one = 'keystone_gateway_info{classifier="none",profile="full",scanner="on"} 0.0\n'
    assert read_info(not_one) == (None, {})
    assert read_info(f'keystone_scanner_classifier_ready{{classifier="{MODEL}"}} 0.0\n')[1] == {
        MODEL: False
    }


class FakeGateway:
    """`/metrics` and `/admin/api/v1/policies` of a gateway whose model loads after `loads_after`
    reads of the metrics page."""

    def __init__(self, loads_after: int = 0, model: str = MODEL) -> None:
        self.model = model
        self.loads_after = loads_after
        self.reads = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/metrics":
            self.reads += 1
            ready = 1 if self.reads > self.loads_after else 0
            info = f'classifier="{self.model}",profile="full",scanner="on"'
            lines = [f"keystone_gateway_info{{{info}}} 1.0"]
            if self.model != "none":
                lines.append(
                    f'keystone_scanner_classifier_ready{{classifier="{self.model}"}} {ready}.0'
                )
            return httpx.Response(200, text="\n".join(lines) + "\n")
        assert request.url.path == "/admin/api/v1/policies"
        return httpx.Response(
            200, json={"version": "v1", "policies": [{"id": p} for p in sorted(RULE_OF_TWO)]}
        )

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(self.handler), base_url="http://keystone.test"
        )


def target() -> Target:
    return Target(
        base_url="http://keystone.test",
        witness=Witness({}),
        tokens=Tokens(agent=lambda: "a", approver=lambda: "p", admin=lambda: "r"),
    )


async def test_the_facts_of_a_gateway_are_its_info_its_model_and_its_policies() -> None:
    found = await gateway_facts(target(), FakeGateway().client())

    assert (found["profile"], found["scanner"], found["classifier"]) == ("full", "on", MODEL)
    assert found["classifier_ready"] is True
    assert found["policies"] == sorted(RULE_OF_TWO) and found["policy_version"] == "v1"
    # A gateway with no model has none to wait for.
    none = await gateway_facts(target(), FakeGateway(model="none").client())
    assert none["classifier"] == "none" and none["classifier_ready"] is None


async def test_a_gateway_that_is_still_loading_its_model_is_asked_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = FakeGateway(loads_after=2)

    async def no_wait(_seconds: float) -> None:
        return None

    monkeypatch.setattr(runner.anyio, "sleep", no_wait)

    found = await facts_with_the_model(target(), gateway.client())

    assert found["classifier_ready"] is True and gateway.reads == 3


async def test_a_model_that_never_loads_is_given_up_on_and_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = FakeGateway(loads_after=10**6)
    clock = iter(range(0, 10**6, 100))
    monkeypatch.setattr(runner.time, "monotonic", lambda: float(next(clock)))

    async def no_wait(_seconds: float) -> None:
        return None

    monkeypatch.setattr(runner.anyio, "sleep", no_wait)

    found = await facts_with_the_model(target(), gateway.client())

    assert found["classifier_ready"] is False and gateway.reads < 10
    with pytest.raises(ConfigMismatch, match=f"its model {MODEL} has not loaded"):
        check_config("C2", found)


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
