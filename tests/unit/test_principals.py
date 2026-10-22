"""KS-303: the claims of a validated token become a Principal, or the token is refused."""

from typing import Any

import pytest

from keystone.identity.jwt import AuthError
from keystone.identity.principals import principal_from_claims
from keystone.settings import AgentConfig

AGENTS = {"support-agent": AgentConfig(trust="standard"), "ops-agent": AgentConfig(trust="high")}
BASE: dict[str, Any] = {
    "sub": "alice",
    "tenant": "acme",
    "azp": "support-agent",
    "groups": ["/tenants/acme", "/support"],
}


def claims(**changes: Any) -> dict[str, Any]:
    merged = {**BASE, **changes}
    return {k: v for k, v in merged.items() if v is not None}


def refused(**changes: Any) -> AuthError:
    with pytest.raises(AuthError) as raised:
        principal_from_claims(claims(**changes), AGENTS)
    return raised.value


@pytest.mark.phase(3)
def test_the_tenant_user_agent_and_groups_come_from_the_claims() -> None:
    principal = principal_from_claims(claims(), AGENTS)

    assert (principal.tenant_id, principal.user_id, principal.agent_id) == (
        "acme",
        "alice",
        "support-agent",
    )
    assert principal.groups == ("support",)
    assert (principal.roles, principal.scopes) == ((), ())


@pytest.mark.phase(3)
def test_groups_lose_the_leading_slash_and_the_tenant_entries() -> None:
    principal = principal_from_claims(
        claims(groups=["/tenants", "/tenants/acme", "/operators", "approvers", "/", ""]), AGENTS
    )

    assert principal.groups == ("operators", "approvers")


@pytest.mark.phase(3)
def test_a_nested_group_keeps_its_path_and_repeats_are_dropped() -> None:
    principal = principal_from_claims(claims(groups=["/teams/support", "/teams/support"]), AGENTS)

    assert principal.groups == ("teams/support",)


@pytest.mark.phase(3)
def test_a_tenant_like_name_that_is_not_under_tenants_is_a_group() -> None:
    assert principal_from_claims(claims(groups=["/tenantsx", "/tenants-ops"]), AGENTS).groups == (
        "tenantsx",
        "tenants-ops",
    )


@pytest.mark.phase(3)
def test_the_agent_is_azp_and_falls_back_to_client_id() -> None:
    by_azp = principal_from_claims(claims(azp="ops-agent", client_id="support-agent"), AGENTS)
    by_client_id = principal_from_claims(claims(azp=None, client_id="ops-agent"), AGENTS)
    empty_azp = principal_from_claims(claims(azp="", client_id="ops-agent"), AGENTS)

    assert by_azp.agent_id == "ops-agent"
    assert by_client_id.agent_id == "ops-agent"
    assert empty_azp.agent_id == "ops-agent"


@pytest.mark.phase(3)
@pytest.mark.parametrize("missing", [{"azp": None}, {"azp": 7}, {"azp": ["support-agent"]}])
def test_a_token_that_names_no_agent_is_refused(missing: dict[str, Any]) -> None:
    error = refused(**missing)

    assert error.reason == "missing_agent" and error.status == 401


@pytest.mark.phase(3)
def test_roles_are_filtered_to_admin_and_approver() -> None:
    roles = ["offline_access", "approver", "default-roles-keystone", "admin", "superuser"]

    principal = principal_from_claims(claims(roles=roles), AGENTS)

    assert principal.roles == ("admin", "approver")


@pytest.mark.phase(3)
def test_roles_come_from_realm_access_when_there_is_no_roles_claim() -> None:
    principal = principal_from_claims(
        claims(realm_access={"roles": ["approver", "uma_authorization"]}), AGENTS
    )

    assert principal.roles == ("approver",)


@pytest.mark.phase(3)
def test_the_roles_claim_wins_over_realm_access() -> None:
    principal = principal_from_claims(
        claims(roles=[], realm_access={"roles": ["admin"]}),
        AGENTS,
    )

    assert principal.roles == ()


@pytest.mark.phase(3)
def test_scopes_come_from_the_scope_claim() -> None:
    principal = principal_from_claims(claims(scope="profile email"), AGENTS)

    assert principal.scopes == ("profile", "email")


@pytest.mark.phase(3)
@pytest.mark.parametrize("tenant", [None, ""])
def test_a_missing_tenant_is_refused(tenant: str | None) -> None:
    error = refused(tenant=tenant)

    assert error.reason == "missing_tenant" and error.status == 401


@pytest.mark.phase(3)
@pytest.mark.parametrize("tenant", ["Acme", "acme corp", "../acme", "1acme", 7, ["acme"], "a" * 64])
def test_a_tenant_that_is_not_a_tenant_id_is_refused(tenant: Any) -> None:
    assert refused(tenant=tenant).reason == "invalid_tenant"


@pytest.mark.phase(3)
@pytest.mark.parametrize("sub", [None, "", 42])
def test_a_token_without_a_usable_subject_is_refused(sub: Any) -> None:
    error = refused(sub=sub)

    assert (error.reason, error.claim) == ("invalid_claim", "sub")


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    "changes",
    [{"groups": "support"}, {"groups": [1, 2]}, {"roles": "admin"}, {"roles": [{"a": 1}]}],
)
def test_a_groups_or_roles_claim_of_the_wrong_shape_is_refused(changes: dict[str, Any]) -> None:
    error = refused(**changes)

    assert error.reason == "invalid_claim" and error.claim in {"groups", "roles"}
