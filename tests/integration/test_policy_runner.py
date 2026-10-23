"""KS-408: the shipped policies keep deciding the shipped cases the same way."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from keystone.admin.cli import app as cli
from keystone.policy.testrunner import load_cases, run

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
CASES = ROOT / "tests" / "policy_cases"


@pytest.mark.phase(4)
def test_policy_cases_all_pass() -> None:
    result = CliRunner().invoke(cli, ["policy", "test", str(POLICIES), str(CASES), "--coverage"])

    assert result.exit_code == 0, result.output
    assert "0 failed" in result.output
    assert "coverage: every policy was matched by at least one case" in result.output
    assert len(load_cases([CASES])) >= 25


@pytest.mark.phase(4)
def test_the_cases_exercise_every_default_and_demo_policy() -> None:
    report = run(POLICIES, [CASES], coverage=True)

    assert report.ok and report.unmatched == ()
    covered = {
        (o.case.case.tenant, reason)
        for o in report.outcomes
        for reason in o.trace.decision.reasons
        if o.passed
    }
    for policy in (
        "same-tenant-low-medium",
        "operators-high",
        "admins-critical",
        "deny-cross-tenant",
        "approve-transfer-over-500",
        "external-email-needs-approval",
        "default-deny",
    ):
        assert any(reason == policy for _, reason in covered), policy


@pytest.mark.phase(4)
def test_the_cases_cover_both_tenants_and_both_actions() -> None:
    cases = [c.case for c in load_cases([CASES])]

    assert {c.tenant for c in cases} == {"acme", "globex"}
    assert {c.action for c in cases} == {"call_tool", "list_tool"}
    assert {c.expect.value for c in cases} == {"allow", "deny", "require_approval"}
    assert len({c.name for c in cases}) == len(cases)
