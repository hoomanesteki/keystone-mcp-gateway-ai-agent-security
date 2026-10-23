"""KS-408: policy cases are checked like code, and a change that flips a decision fails."""

import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from keystone.admin.cli import app as cli
from keystone.policy.testrunner import CaseError, load_cases, render, run
from tests.fixtures.policies import forbid, permit, write_policies

ALLOW_LOW = permit("allow-low", "resource.risk_level <= 2")
CASES = Path(__file__).resolve().parents[1] / "policy_cases"


def tree(tmp_path: Path, **files: str) -> Path:
    named = {key.replace("__", "/") + ".cedar": text for key, text in files.items()}
    named.setdefault("default/access/base.cedar", ALLOW_LOW)
    return write_policies(tmp_path / "policies", named)


def case_file(tmp_path: Path, body: str, name: str = "cases.yaml") -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body))
    return path


def one_case(expect: str = "allow", reasons: str = "[allow-low]", tool_risk: str = "low") -> str:
    return f"""
    - name: support reads mail
      tenant: acme
      principal: {{user: alice, groups: [support]}}
      tool: {{name: mail__read_email, risk: {tool_risk}}}
      expect: {expect}
      expect_reasons: {reasons}
    """


def cli_run(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(cli, ["policy", "test", *args])
    return result.exit_code, result.output


@pytest.mark.phase(4)
def test_runner_reports_failure(tmp_path: Path) -> None:
    root = tree(tmp_path)
    cases = case_file(tmp_path, one_case(expect="deny", reasons="[default-deny]"))

    report = run(root, [cases])
    code, output = cli_run(str(root), str(cases))

    [failed] = report.failed
    assert failed.case.case.name == "support reads mail"
    assert failed.problems == (
        "expected deny, got allow",
        "expected reasons ['default-deny'], got ['allow-low']",
    )
    assert not report.ok
    assert code == 1
    assert "FAIL" in output and "'support reads mail'" in output  # the case is named
    assert "expected deny, got allow" in output
    assert "1 cases, 0 passed, 1 failed" in output


@pytest.mark.phase(4)
def test_runner_coverage_lists_unmatched(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        default__access__more=permit("allow-high", "resource.risk_level == 3")
        + forbid("freeze-friday", "context.hour_utc == 5"),
        acme__approval__ask=permit("ask-for-big", "false"),
    )
    cases = case_file(tmp_path, one_case())

    plain = run(root, [cases])
    covered = run(root, [cases], coverage=True)
    code, output = cli_run(str(root), str(cases), "--coverage")

    assert plain.ok and plain.unmatched == ()  # without --coverage nothing is listed or enforced
    assert [(u.file, u.id) for u in covered.unmatched] == [
        ("acme/approval/ask.cedar", "ask-for-big"),
        ("default/access/more.cedar", "allow-high"),
        ("default/access/more.cedar", "freeze-friday"),
    ]
    assert not covered.ok
    assert code == 1
    assert "coverage: 3 policies no case matched:" in output
    assert "  default/access/more.cedar: freeze-friday" in output
    assert "1 cases, 1 passed, 0 failed" in output


@pytest.mark.phase(4)
def test_every_policy_matched_gives_a_clean_exit(tmp_path: Path) -> None:
    root = tree(tmp_path)
    cases = case_file(tmp_path, one_case())

    code, output = cli_run(str(root), str(cases), "--coverage")

    assert code == 0
    assert "coverage: every policy was matched by at least one case" in output


@pytest.mark.phase(4)
def test_flipping_one_expectation_of_the_shipped_cases_fails_and_names_the_case(
    tmp_path: Path,
) -> None:
    text = (CASES / "default.yaml").read_text()
    marker = "- name: support cannot transfer\n"
    start = text.index(marker)
    end = text.index("expect_reasons", start)
    flipped = text[:start] + text[start:end].replace("expect: deny", "expect: allow") + text[end:]
    assert flipped != text
    edited = tmp_path / "default.yaml"
    edited.write_text(flipped)
    policies = Path(__file__).resolve().parents[2] / "policies"

    code, output = cli_run(str(policies), str(edited))

    assert code == 1
    assert "FAIL 'support cannot transfer'" in output
    assert "expected allow, got deny" in output
    assert output.count("FAIL '") == 1  # and only that one


@pytest.mark.phase(4)
def test_reasons_are_compared_without_regard_to_order(tmp_path: Path) -> None:
    root = tree(tmp_path, default__access__two=permit("also-low", "resource.risk_level <= 2"))
    cases = case_file(tmp_path, one_case(reasons="[also-low, allow-low]"))

    assert run(root, [cases]).ok


@pytest.mark.phase(4)
def test_a_case_without_expect_reasons_checks_only_the_effect(tmp_path: Path) -> None:
    root = tree(tmp_path)
    cases = case_file(
        tmp_path,
        """
        - name: any reason will do
          tenant: acme
          principal: {user: alice}
          tool: {name: mail__read_email, risk: low}
          expect: allow
        """,
    )

    assert run(root, [cases]).ok


@pytest.mark.phase(4)
def test_the_three_effects_and_the_list_action(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        acme__approval__ask=permit(
            "ask-on-ten", "context.args has count && context.args.count > 9"
        ),
    )
    cases = case_file(
        tmp_path,
        """
        - name: allowed
          tenant: acme
          principal: {user: alice}
          tool: {name: bank__get_balance, risk: medium}
          expect: allow
        - name: refused
          tenant: acme
          principal: {user: alice}
          tool: {name: bank__transfer, risk: high}
          expect: deny
          expect_reasons: [default-deny]
        - name: asked
          tenant: acme
          principal: {user: alice}
          tool: {name: bank__get_balance, risk: medium}
          args: {count: 10}
          expect: require_approval
          expect_reasons: [ask-on-ten]
        - name: a listing does not ask
          tenant: acme
          principal: {user: alice}
          tool: {name: bank__get_balance, risk: medium}
          args: {count: 10}
          action: list_tool
          expect: allow
        """,
    )

    report = run(root, [cases])

    assert report.ok and len(report.outcomes) == 4


@pytest.mark.phase(4)
def test_the_session_hour_and_roles_reach_the_policies(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        default__access__rules=(
            forbid(
                "late-flagged",
                'context.hour_utc >= 22 && context.session_flags.contains("reads_untrusted")',
            )
            + forbid("tainted-and-busy", "context.session_tainted && context.call_count > 5")
        ),
    )
    cases = case_file(
        tmp_path,
        """
        - name: late with a flag
          tenant: acme
          principal: {user: alice}
          tool: {name: mail__read_email, risk: low}
          session: {flags: [reads_untrusted]}
          hour: 23
          expect: deny
          expect_reasons: [late-flagged]
        - name: late without the flag
          tenant: acme
          principal: {user: alice}
          tool: {name: mail__read_email, risk: low}
          hour: 23
          expect: allow
        - name: tainted and busy
          tenant: acme
          principal: {user: alice}
          tool: {name: mail__read_email, risk: low}
          session: {tainted: true, call_count: 6}
          expect: deny
          expect_reasons: [tainted-and-busy]
        """,
    )

    assert run(root, [cases]).ok


@pytest.mark.phase(4)
def test_arguments_run_through_the_extractors_and_args_are_taken_as_given(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        acme__approval__ask=permit(
            "ask-over-500", "context.args has amount && context.args.amount > 50000"
        ),
    )
    cases = case_file(
        tmp_path,
        """
        - name: from the call's arguments
          tenant: acme
          principal: {user: alice}
          tool: {name: bank__get_balance, risk: medium, extract: {amount: "$.amount | cents"}}
          arguments: {amount: 500.01}
          expect: require_approval
        - name: from the facts
          tenant: acme
          principal: {user: alice}
          tool: {name: bank__get_balance, risk: medium}
          args: {amount: 50000}
          expect: allow
        """,
    )

    assert run(root, [cases]).ok


@pytest.mark.phase(4)
def test_a_case_in_a_tenant_with_its_own_directory_is_decided_by_it(tmp_path: Path) -> None:
    root = tree(tmp_path, globex__access__freeze=forbid("globex-freeze"))
    cases = case_file(
        tmp_path,
        """
        - name: acme is not frozen
          tenant: acme
          principal: {user: alice}
          tool: {name: mail__read_email, risk: low}
          expect: allow
        - name: globex is
          tenant: globex
          principal: {user: bob}
          tool: {name: mail__read_email, risk: low}
          expect: deny
          expect_reasons: [globex-freeze]
        """,
    )

    assert run(root, [cases]).ok


@pytest.mark.phase(4)
def test_a_case_that_ends_in_a_policy_error_shows_why(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        default__access__broken=forbid("overflows", "context.call_count + 9223372036854775807 > 0"),
    )
    cases = case_file(
        tmp_path,
        """
        - name: errors out
          tenant: acme
          principal: {user: alice}
          tool: {name: mail__read_email, risk: low}
          session: {call_count: 5}
          expect: deny
          expect_reasons: [policy-error]
        """,
    )

    report = run(root, [cases])

    assert report.ok
    assert any("policy_evaluation_failed" in note for note in report.notes)
    assert "the engine logged:" in render(report)


VALID: dict[str, Any] = {
    "name": "x",
    "tenant": "acme",
    "principal": {"user": "a"},
    "tool": {"name": "a__b"},
    "expect": "allow",
}


def document(*cases: dict[str, Any]) -> str:
    return yaml.safe_dump(list(cases))


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        (document({**VALID, "expect": "maybe"}), "expect"),
        (document({k: v for k, v in VALID.items() if k != "expect"}), "expect: Field required"),
        (document({**VALID, "extra": 1}), "extra: Extra inputs"),
        (document({**VALID, "principal": {"user": "a", "grops": ["s"]}}), "principal.grops"),
        (document({**VALID, "tool": {"name": "nounderscore"}}), "tool.name"),
        (document({**VALID, "tool": {"name": "a__b", "risk": "huge"}}), "tool.risk"),
        (document({**VALID, "tool": {"name": "a__b", "tags": ["nope"]}}), "tool.tags"),
        (document({**VALID, "hour": 24}), "hour"),
        (
            document({**VALID, "args": {"a": 1}, "arguments": {"a": 1}}),
            "args or arguments, not both",
        ),
        (document(VALID, VALID), "same name"),
        ("name: not a list\n", "a case file is a list of cases"),
        ("- [unterminated\n", "cannot be read as YAML"),
    ],
)
def test_a_case_file_with_a_mistake_is_refused_with_the_mistake_named(
    tmp_path: Path, body: str, fragment: str
) -> None:
    path = case_file(tmp_path, body)

    with pytest.raises(CaseError) as raised:
        load_cases([path])

    assert any(fragment in problem and str(path) in problem for problem in raised.value.problems)


@pytest.mark.phase(4)
def test_the_cli_says_what_it_cannot_read(tmp_path: Path) -> None:
    good = case_file(tmp_path, one_case())
    broken_cases = case_file(tmp_path, "- name: x\n", name="broken.yaml")

    missing_cases = cli_run(str(tree(tmp_path)), str(tmp_path / "nowhere.yaml"))
    bad_cases = cli_run(str(tree(tmp_path / "t2")), str(broken_cases))
    bad_policy = cli_run(str(tmp_path / "no-policies"), str(good))

    assert missing_cases[0] == 1 and "no such file or directory" in missing_cases[1]
    assert bad_cases[0] == 1 and "the cases cannot be read" in bad_cases[1]
    assert bad_policy[0] == 1 and "the policies cannot be loaded" in bad_policy[1]
    assert "does not exist" in bad_policy[1]


@pytest.mark.phase(4)
def test_a_directory_of_cases_is_read_in_a_stable_order(tmp_path: Path) -> None:
    folder = tmp_path / "cases"
    folder.mkdir()
    case_file(folder, one_case().replace("support reads mail", "second"), name="b.yaml")
    case_file(folder, one_case().replace("support reads mail", "first"), name="a.yml")
    (folder / "notes.txt").write_text("not a case file")

    loaded = load_cases([folder])

    assert [c.case.name for c in loaded] == ["first", "second"]


@pytest.mark.phase(4)
def test_a_long_case_name_is_cut_in_the_table_and_whole_in_the_failure(tmp_path: Path) -> None:
    root = tree(tmp_path)
    name = "a case with a name that is much longer than the table is willing to show in one cell"
    cases = case_file(
        tmp_path, one_case(expect="deny", reasons="[x]").replace("support reads mail", name)
    )

    output = render(run(root, [cases]))

    assert name[:40] in output and "..." in output
    assert f"FAIL {name!r}" in output
