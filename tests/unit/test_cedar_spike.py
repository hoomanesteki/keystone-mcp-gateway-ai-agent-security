"""KS-401: what cedarpy does, pinned as tests (docs/spikes/cedarpy.md has the findings).

These call cedarpy directly. The policy engine reaches it through one adapter (keystone.policy),
so a cedarpy upgrade that changes any behavior below fails here first, with the behavior named.
The schema is the one in plan section 3.8.
"""

import json
import statistics
import time
from typing import Any

import pytest
from cedarpy import (
    Decision,
    PolicySet,
    Schema,
    is_authorized,
    policies_to_json_str,
    validate_policies,
)

SCHEMA = """
namespace Keystone {
  entity Tenant;
  entity Group;
  entity User in [Group] { tenant: Tenant };
  entity Upstream { tenant: Tenant };
  entity Tool in [Upstream] {
    tenant: Tenant,
    risk: String,          // "low" | "medium" | "high" | "critical"
    risk_level: Long,      // 1..4, for comparisons
    tags: Set<String>,
  };
  action list_tool, call_tool appliesTo {
    principal: [User],
    resource: [Tool],
    context: {
      agent_id: String,
      agent_trust: String,
      session_flags: Set<String>,
      session_tainted: Bool,
      call_count: Long,
      hour_utc: Long,
      args: { amount?: Long, recipient_domain?: String, path?: String, count?: Long },
    }
  };
}
"""

POLICIES = """
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

@id("rule-of-two")
permit (principal, action == Keystone::Action::"call_tool", resource)
when { resource.tags.contains("external_effect")
       && context.session_flags.contains("reads_untrusted")
       && context.session_flags.contains("reads_sensitive") };

@id("approve-transfer-over-500")
permit (
  principal,
  action == Keystone::Action::"call_tool",
  resource == Keystone::Tool::"bank__transfer"
)
when { context.args has amount && context.args.amount > 500 };
"""

# The order above. Cedar numbers surface-syntax policies by position, per parse.
POSITIONAL_TO_ID = {
    "policy0": "same-tenant-low-medium",
    "policy1": "operators-high",
    "policy2": "deny-cross-tenant",
    "policy3": "rule-of-two",
    "policy4": "approve-transfer-over-500",
}


def uid(kind: str, name: str) -> dict[str, str]:
    return {"type": f"Keystone::{kind}", "id": name}


def entity(
    kind: str,
    name: str,
    attrs: dict[str, Any] | None = None,
    parents: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {"uid": uid(kind, name), "attrs": attrs or {}, "parents": parents or []}


def tenant_ref(name: str) -> dict[str, Any]:
    return {"__entity": uid("Tenant", name)}


def entities(
    groups: tuple[str, ...] = ("operators",),
    tool_tenant: str = "acme",
    risk_level: int = 3,
    tags: tuple[str, ...] = ("external_effect",),
) -> list[dict[str, Any]]:
    found = [entity("Tenant", "acme"), entity("Tenant", "globex")]
    found += [entity("Group", g) for g in groups]
    found.append(
        entity(
            "User", "acme:olivia", {"tenant": tenant_ref("acme")}, [uid("Group", g) for g in groups]
        )
    )
    found.append(entity("Upstream", "bank", {"tenant": tenant_ref(tool_tenant)}))
    found.append(
        entity(
            "Tool",
            "bank__transfer",
            {
                "tenant": tenant_ref(tool_tenant),
                "risk": "high",
                "risk_level": risk_level,
                "tags": list(tags),
            },
            [uid("Upstream", "bank")],
        )
    )
    return found


def request(
    action: str = "call_tool", flags: tuple[str, ...] = (), amount: int | None = 900
) -> dict[str, Any]:
    return {
        "principal": uid("User", "acme:olivia"),
        "action": uid("Action", action),
        "resource": uid("Tool", "bank__transfer"),
        "context": {
            "agent_id": "ops-agent",
            "agent_trust": "high",
            "session_flags": list(flags),
            "session_tainted": False,
            "call_count": 0,
            "hour_utc": 12,
            "args": {} if amount is None else {"amount": amount},
        },
    }


@pytest.mark.phase(4)
def test_policy_id_annotation_mapping() -> None:
    schema = Schema.from_str(SCHEMA)
    policies = PolicySet.from_str(POLICIES)

    # An allow reports every permit that matched, by Cedar's positional id.
    allowed = is_authorized(request(), policies, entities(), schema=schema)
    assert allowed.decision is Decision.Allow
    assert sorted(allowed.diagnostics.reasons) == ["policy1", "policy4"]
    assert allowed.diagnostics.id_annotations_by_reason == {
        "policy1": "operators-high",
        "policy4": "approve-transfer-over-500",
    }

    # A deny by a forbid reports the forbid, and only the forbid.
    crossed = is_authorized(request(), policies, entities(tool_tenant="globex"), schema=schema)
    assert crossed.decision is Decision.Deny
    assert crossed.diagnostics.reasons == ["policy2"]
    assert crossed.diagnostics.id_annotations_by_reason == {"policy2": "deny-cross-tenant"}

    # No permit and no forbid matched: a deny with no reasons at all. The engine names this case.
    unmatched = request(amount=None)
    nothing = is_authorized(unmatched, policies, entities(groups=(), risk_level=4), schema=schema)
    assert nothing.decision is Decision.Deny
    assert nothing.diagnostics.reasons == nothing.diagnostics.errors == []

    # The JSON form of the same text numbers the policies the same way and carries each @id and
    # effect, which is how the loader learns the id and the effect of every policy it holds.
    parsed = json.loads(policies_to_json_str(POLICIES))["staticPolicies"]
    assert {key: policy["annotations"]["id"] for key, policy in parsed.items()} == POSITIONAL_TO_ID
    assert {key: policy["effect"] for key, policy in parsed.items()} == {
        "policy0": "permit",
        "policy1": "permit",
        "policy2": "forbid",
        "policy3": "permit",
        "policy4": "permit",
    }


@pytest.mark.phase(4)
def test_the_human_readable_schema_is_accepted_as_it_is() -> None:
    schema = Schema.from_str(SCHEMA)

    assert validate_policies(POLICIES, schema).validation_passed
    # A schema passed as text works too, for a caller that does not keep a handle.
    assert is_authorized(request(), POLICIES, entities(), schema=SCHEMA).allowed
    with pytest.raises(ValueError, match="unexpected token"):
        Schema.from_str("namespace Keystone { entity }")


@pytest.mark.phase(4)
def test_validation_names_the_policy_by_its_id() -> None:
    schema = Schema.from_str(SCHEMA)
    typo = '@id("typo") permit (principal, action, resource) when { resource.rsik_level <= 2 };'
    unsafe = '@id("no-has") permit (principal, action, resource) when { context.args.amount > 1 };'

    typo_result = validate_policies(typo, schema)
    unsafe_result = validate_policies(unsafe, schema)

    assert not typo_result.validation_passed
    assert typo_result.id_annotations_by_policy_id == {"policy0": "typo"}
    assert "rsik_level" in str(typo_result.errors[0])
    assert not unsafe_result.validation_passed
    assert "optional attribute" in str(unsafe_result.errors[0])
    # Cedar does not require an @id and does not mind two policies sharing one. The loader does.
    bare = "permit (principal, action, resource) when { true };"
    twice = '@id("a") ' + bare + '\n@id("a") ' + bare
    assert validate_policies(bare, schema).validation_passed
    assert validate_policies(twice, schema).validation_passed
    # A syntax error raises when the set is parsed, with no file and no line in the message.
    with pytest.raises(ValueError, match="unexpected end of input"):
        PolicySet.from_str("permit (principal, action, resource")


@pytest.mark.phase(4)
def test_a_request_that_does_not_fit_the_schema_is_no_decision() -> None:
    schema = Schema.from_str(SCHEMA)
    policies = PolicySet.from_str(POLICIES)
    missing = request()
    del missing["context"]["hour_utc"]
    unknown_key = request()
    unknown_key["context"]["args"]["bogus"] = 1
    wrong_type = request()
    wrong_type["context"]["call_count"] = "many"

    for bad in (missing, unknown_key, wrong_type):
        result = is_authorized(bad, policies, entities(), schema=schema)
        # Neither Allow nor Deny: the engine must not read this as either.
        assert result.decision is Decision.NoDecision
        assert result.diagnostics.errors and not result.allowed
    shaped_wrong = entities()
    shaped_wrong[-1]["attrs"]["risk_level"] = "3"
    assert is_authorized(request(), policies, shaped_wrong, schema=schema).decision is (
        Decision.NoDecision
    )


@pytest.mark.phase(4)
def test_an_error_in_a_policy_is_reported_but_does_not_stop_the_decision() -> None:
    # Cedar skips a policy that fails to evaluate. When that policy is a forbid, the decision is
    # still Allow, so the engine treats any entry in `errors` as a failure of its own.
    policies = PolicySet.from_str(
        '@id("broken-forbid") forbid (principal, action, resource) when { resource.nope > 1 };\n'
        '@id("fine") permit (principal, action, resource);'
    )

    result = is_authorized(request(), policies, entities())

    assert result.decision is Decision.Allow
    assert result.diagnostics.reasons == ["policy1"]
    assert len(result.diagnostics.errors) == 1
    assert "policy0" in result.diagnostics.errors[0]


@pytest.mark.phase(4)
def test_a_missing_entity_is_a_list_of_errors_not_no_decision() -> None:
    # The tool entity is absent. Every policy that reads it reports an error, and a permit that
    # does not read it still allows the call.
    policies = PolicySet.from_str(POLICIES)
    without_the_tool = [e for e in entities() if e["uid"]["type"] != "Keystone::Tool"]

    result = is_authorized(request(), policies, without_the_tool, schema=Schema.from_str(SCHEMA))

    assert result.decision is Decision.Allow
    assert result.diagnostics.id_annotations_by_reason == {"policy4": "approve-transfer-over-500"}
    assert any("does not exist" in error for error in result.diagnostics.errors)


@pytest.mark.phase(4)
def test_an_empty_policy_set_denies() -> None:
    result = is_authorized(request(), PolicySet.from_str(""), entities())

    assert result.decision is Decision.Deny
    assert result.diagnostics.reasons == []


@pytest.mark.phase(4)
def test_the_attribute_named_tags_is_not_an_entity_tag() -> None:
    schema = Schema.from_str(SCHEMA)
    policies = PolicySet.from_str(POLICIES)
    flags = ("reads_untrusted", "reads_sensitive")

    with_tag = is_authorized(
        request(flags=flags, amount=None), policies, entities(groups=()), schema=schema
    )
    without_tag = is_authorized(
        request(flags=flags, amount=None), policies, entities(groups=(), tags=()), schema=schema
    )

    # `resource.tags.contains(...)` reads the attribute, in the schema, in a policy and at runtime.
    assert with_tag.decision is Decision.Allow
    assert with_tag.diagnostics.id_annotations_by_reason == {"policy3": "rule-of-two"}
    assert without_tag.decision is Decision.Deny
    # Entity tags are a separate field of the entity JSON. This schema declares none, so an entity
    # that carries them is refused, which is why the entity builder writes `attrs.tags` only.
    tagged = entities(groups=())
    tagged[-1]["tags"] = {"x": "y"}
    assert is_authorized(request(), policies, tagged, schema=schema).decision is Decision.NoDecision


@pytest.mark.phase(4)
def test_a_parsed_handle_is_not_parsed_again() -> None:
    schema = Schema.from_str(SCHEMA)
    policies = PolicySet.from_str(POLICIES)

    from_text = is_authorized(request(), POLICIES, entities(), schema=SCHEMA)
    from_handles = is_authorized(request(), policies, entities(), schema=schema)

    assert from_text.metrics["policies_pre_parsed"] == 0
    assert from_text.metrics["schema_pre_parsed"] == 0
    assert from_handles.metrics["policies_pre_parsed"] == 1
    assert from_handles.metrics["schema_pre_parsed"] == 1
    assert from_handles.metrics["parse_policies_duration_micros"] == 0
    assert from_handles.decision is from_text.decision


@pytest.mark.phase(4)
def test_reusing_the_handles_keeps_50_policies_and_20_entities_fast() -> None:
    filler = "\n".join(
        f'@id("approve-tool-{i}") permit (principal, action == Keystone::Action::"call_tool", '
        f'resource == Keystone::Tool::"tool{i}__go") when {{ context.args has amount '
        f'&& context.args.amount > {100 + i} && resource.tags.contains("external_effect") }};'
        for i in range(45)
    )
    schema = Schema.from_str(SCHEMA)
    policies = PolicySet.from_str(POLICIES + filler)
    found = entities()
    found += [entity("Group", f"extra{i}") for i in range(20 - len(found))]
    assert len(policies) == 50 and len(found) == 20
    wanted = request()
    for _ in range(50):  # warm up
        is_authorized(wanted, policies, found, schema=schema)

    samples = []
    for _ in range(1_000):
        started = time.perf_counter()
        result = is_authorized(wanted, policies, found, schema=schema)
        samples.append((time.perf_counter() - started) * 1000)

    samples.sort()
    p95 = samples[int(0.95 * (len(samples) - 1))]
    assert result.allowed
    # Typically 0.5 ms on a laptop (docs/spikes/cedarpy.md). The budget leaves room for a slow
    # CI runner; the point is that parsing the policies on every call would take 5 times as long.
    assert p95 < 5.0, f"p50 {statistics.median(samples):.2f} ms, p95 {p95:.2f} ms"
