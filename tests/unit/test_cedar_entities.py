"""KS-402: principals, tools and the call context become Cedar entities the schema accepts."""

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from keystone.core.types import (
    RISK_LEVEL,
    CallContext,
    Principal,
    Risk,
    SessionState,
    ToolRef,
    ToolTag,
)
from keystone.policy.cedar import CedarSchema, CedarVerdict, CompiledPolicies, authorize
from keystone.policy.entities import (
    Action,
    action_uid,
    build_context,
    build_entities,
    build_request,
    tool_uid,
    user_uid,
)
from tests.fixtures.calls import make_ctx, make_tool

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_FILE = ROOT / "policies" / "schema.cedarschema"
SCHEMA = CedarSchema.from_file(SCHEMA_FILE)

OLIVIA = Principal(
    tenant_id="acme",
    user_id="olivia",
    groups=("operators",),
    agent_id="ops-agent",
    agent_trust="high",
)
ALICE = Principal(tenant_id="acme", user_id="alice", groups=("support",), agent_id="support-agent")
TRANSFER = make_tool("bank", "transfer", risk=Risk.HIGH, tags=frozenset({ToolTag.EXTERNAL_EFFECT}))

# The access rules of plan section 3.8, enough to see the entities do their job.
BASE = CompiledPolicies.from_text(
    """
@id("same-tenant-low-medium")
permit (
  principal,
  action in [Keystone::Action::"list_tool", Keystone::Action::"call_tool"],
  resource
)
when { resource.tenant == principal.tenant && resource.risk_level <= 2 };

@id("operators-high")
permit (principal in Keystone::Group::"operators", action, resource)
when { resource.tenant == principal.tenant && resource.risk_level == 3 };

@id("deny-cross-tenant")
forbid (principal, action, resource) unless { resource.tenant == principal.tenant };
"""
)


def decide(
    principal: Principal,
    tool: ToolRef,
    action: Action = "call_tool",
    extracted: dict[str, int | str | bool] | None = None,
    policies: CompiledPolicies = BASE,
) -> CedarVerdict:
    call = make_ctx(tool=tool, principal=principal)
    context = build_context(call, extracted or {})
    return authorize(
        policies,
        SCHEMA,
        build_entities(principal, tool),
        build_request(principal, action, tool, context),
    )


def by_uid(entities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {f"{e['uid']['type']}::{e['uid']['id']}": e for e in entities}


@pytest.mark.phase(4)
def test_entities_for_principal_and_tool() -> None:
    found = by_uid(build_entities(OLIVIA, TRANSFER))

    assert sorted(found) == [
        "Keystone::Group::operators",
        "Keystone::Tenant::acme",
        "Keystone::Tool::bank__transfer",
        "Keystone::Upstream::bank",
        "Keystone::User::acme:olivia",
    ]
    acme = {"__entity": {"type": "Keystone::Tenant", "id": "acme"}}
    assert found["Keystone::User::acme:olivia"] == {
        "uid": {"type": "Keystone::User", "id": "acme:olivia"},
        "attrs": {"tenant": acme},
        "parents": [{"type": "Keystone::Group", "id": "operators"}],
    }
    assert found["Keystone::Upstream::bank"]["attrs"] == {"tenant": acme}
    assert found["Keystone::Tool::bank__transfer"] == {
        "uid": {"type": "Keystone::Tool", "id": "bank__transfer"},
        "attrs": {"tenant": acme, "risk": "high", "risk_level": 3, "tags": ["external_effect"]},
        "parents": [{"type": "Keystone::Upstream", "id": "bank"}],
    }
    # The tags are an attribute. The entity's own `tags` field is Cedar's entity tags, which the
    # schema does not declare, so an entity that carried it would be refused (the spike).
    assert all("tags" not in entity for entity in found.values())


@pytest.mark.phase(4)
def test_the_entities_decide_who_may_use_what() -> None:
    assert decide(OLIVIA, TRANSFER).reasons == ("operators-high",)
    assert decide(ALICE, TRANSFER).decision == "deny"  # no permit matches: a default deny
    assert decide(ALICE, TRANSFER).reasons == ()
    low = make_tool("mail", "read_email", risk=Risk.LOW)
    assert decide(ALICE, low).reasons == ("same-tenant-low-medium",)
    # A request the schema accepts is never NoDecision, whatever the answer.
    for principal in (OLIVIA, ALICE):
        for tool in (TRANSFER, low):
            assert decide(principal, tool).errors == ()


@pytest.mark.phase(4)
def test_context_matches_schema() -> None:
    session = SessionState(
        session_id="s1",
        principal=OLIVIA,
        flags={ToolTag.READS_UNTRUSTED, ToolTag.READS_SENSITIVE},
        tainted=True,
        call_count=7,
        created_at=datetime(2026, 10, 22, 8, 0, tzinfo=UTC),
    )
    when = datetime(2026, 10, 22, 21, 30, tzinfo=timezone(timedelta(hours=-3)))  # 00:30 UTC
    call = make_ctx(tool=TRANSFER, principal=OLIVIA, session=session, received_at=when)

    context = build_context(call, {"amount": 900, "recipient_domain": "acme.test"})

    assert context == {
        "agent_id": "ops-agent",
        "agent_trust": "high",
        "session_flags": ["reads_sensitive", "reads_untrusted"],
        "session_tainted": True,
        "call_count": 7,
        "hour_utc": 0,
        "args": {"amount": 900, "recipient_domain": "acme.test"},
    }
    allow_all = CompiledPolicies.from_text('@id("any") permit (principal, action, resource);')
    # The schema checks every field's presence and type, and refuses an unknown key in `args`.
    verdict = authorize(
        allow_all,
        SCHEMA,
        build_entities(OLIVIA, TRANSFER),
        build_request(OLIVIA, "call_tool", TRANSFER, context),
    )
    assert (verdict.decision, verdict.errors) == ("allow", ())


@pytest.mark.phase(4)
def test_context_defaults_are_the_quiet_session() -> None:
    call = make_ctx(tool=TRANSFER, principal=OLIVIA)

    context = build_context(call, {})

    assert context["session_flags"] == []
    assert context["session_tainted"] is False
    assert context["call_count"] == 0
    assert context["args"] == {}
    assert context["hour_utc"] == call.received_at.astimezone(UTC).hour


@pytest.mark.phase(4)
def test_a_session_alone_is_enough_to_build_a_context_for_a_list() -> None:
    session = SessionState(
        session_id="s1", principal=ALICE, created_at=datetime(2026, 10, 22, tzinfo=UTC)
    )

    context = build_context(session, {}, now=datetime(2026, 10, 22, 17, 5, tzinfo=UTC))

    assert context["agent_id"] == "support-agent"
    assert context["agent_trust"] == "standard"
    assert context["hour_utc"] == 17
    assert decide(ALICE, make_tool("mail", "read_email", risk=Risk.LOW), "list_tool").reasons == (
        "same-tenant-low-medium",
    )


@pytest.mark.phase(4)
def test_context_args_default_to_what_the_call_extracted() -> None:
    call = make_ctx(tool=TRANSFER, principal=OLIVIA, extracted={"amount": 5})

    assert build_context(call)["args"] == {"amount": 5}
    assert build_context(call, {"amount": 6})["args"] == {"amount": 6}


@pytest.mark.phase(4)
def test_user_uid_is_tenant_qualified() -> None:
    assert user_uid("acme", "olivia") == {"type": "Keystone::User", "id": "acme:olivia"}
    assert user_uid("globex", "olivia") == {"type": "Keystone::User", "id": "globex:olivia"}

    same_name_elsewhere = OLIVIA.model_copy(update={"tenant_id": "globex"})
    here = by_uid(build_entities(OLIVIA, TRANSFER))
    there = by_uid(build_entities(same_name_elsewhere, TRANSFER))
    assert "Keystone::User::acme:olivia" in here and "Keystone::User::acme:olivia" not in there
    assert "Keystone::User::globex:olivia" in there

    # A policy that names acme's olivia does not match globex's.
    named = CompiledPolicies.from_text(
        '@id("acme-olivia") permit (principal == Keystone::User::"acme:olivia", action, resource);'
    )
    low = make_tool("mail", "read_email", risk=Risk.LOW)
    assert decide(OLIVIA, low, policies=named).reasons == ("acme-olivia",)
    globex_tool = low.model_copy(update={"tenant_id": "globex"})
    assert decide(same_name_elsewhere, globex_tool, policies=named).reasons == ()


@pytest.mark.phase(4)
def test_a_tool_of_another_tenant_is_forbidden_by_the_tenant_rule() -> None:
    other = make_tool("mail", "read_email", risk=Risk.LOW).model_copy(
        update={"tenant_id": "globex"}
    )

    verdict = decide(OLIVIA, other)

    assert (verdict.decision, verdict.reasons) == ("deny", ("deny-cross-tenant",))
    found = by_uid(build_entities(OLIVIA, other))
    assert "Keystone::Tenant::globex" in found and "Keystone::Tenant::acme" in found


@pytest.mark.phase(4)
@pytest.mark.parametrize("risk", list(Risk))
def test_every_risk_has_its_numeric_level(risk: Risk) -> None:
    tool = make_tool("echo", "echo", risk=risk)

    attrs = by_uid(build_entities(OLIVIA, tool))["Keystone::Tool::echo__echo"]["attrs"]

    assert attrs["risk"] == risk.value
    assert attrs["risk_level"] == RISK_LEVEL[risk]


@pytest.mark.phase(4)
def test_ids_with_quotes_slashes_and_newlines_are_passed_as_they_are() -> None:
    nasty = Principal(
        tenant_id="acme",
        user_id='o"livia\\ \n::Keystone::Tool::"x',
        groups=('ops "team"', "back\\slash"),
        agent_id="ops-agent",
    )
    low = make_tool("mail", "read_email", risk=Risk.LOW)

    verdict = decide(nasty, low)

    assert (verdict.decision, verdict.errors) == ("allow", ())
    assert user_uid("acme", nasty.user_id)["id"] == 'acme:o"livia\\ \n::Keystone::Tool::"x'


@pytest.mark.phase(4)
def test_no_group_and_a_repeated_group_are_both_fine() -> None:
    plain = ALICE.model_copy(update={"groups": ()})
    twice = ALICE.model_copy(update={"groups": ("support", "support")})

    assert [e["uid"]["type"] for e in build_entities(plain, TRANSFER)].count("Keystone::Group") == 0
    assert [
        e["uid"]["id"]
        for e in build_entities(twice, TRANSFER)
        if e["uid"]["type"] == "Keystone::Group"
    ] == ["support"]
    assert decide(plain, TRANSFER).errors == decide(twice, TRANSFER).errors == ()


@pytest.mark.phase(4)
def test_uids_and_the_request_name_the_action_and_the_tool() -> None:
    assert action_uid("call_tool") == {"type": "Keystone::Action", "id": "call_tool"}
    assert action_uid("list_tool") == {"type": "Keystone::Action", "id": "list_tool"}
    assert tool_uid("bank__transfer") == {"type": "Keystone::Tool", "id": "bank__transfer"}

    request = build_request(OLIVIA, "call_tool", TRANSFER, {"k": "v"})

    assert request == {
        "principal": {"type": "Keystone::User", "id": "acme:olivia"},
        "action": {"type": "Keystone::Action", "id": "call_tool"},
        "resource": {"type": "Keystone::Tool", "id": "bank__transfer"},
        "context": {"k": "v"},
    }


@pytest.mark.phase(4)
def test_an_unknown_args_key_is_refused_by_the_schema_not_dropped() -> None:
    call: CallContext = make_ctx(tool=TRANSFER, principal=OLIVIA)
    context = build_context(call, {"to": "x"})  # `to` is not in the schema's args record

    verdict = authorize(
        BASE,
        SCHEMA,
        build_entities(OLIVIA, TRANSFER),
        build_request(OLIVIA, "call_tool", TRANSFER, context),
    )

    assert verdict.decision == "none"
    assert any("should not exist" in error for error in verdict.errors)


@pytest.mark.phase(4)
def test_the_schema_file_is_plan_section_3_8_verbatim() -> None:
    plan = (ROOT / "docs" / "PLAN.md").read_text().splitlines()
    heading = next(i for i, line in enumerate(plan) if line.startswith("### 3.8 "))
    start = next(i for i in range(heading, len(plan)) if plan[i].startswith("```")) + 1
    end = next(i for i in range(start, len(plan)) if plan[i].startswith("```"))
    block = plan[start:end]

    assert block[0] == "// policies/schema.cedarschema"  # the name of the file, not part of it
    assert SCHEMA_FILE.read_text() == "\n".join(block[1:]) + "\n"
