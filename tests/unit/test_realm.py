"""The Keycloak realm file (KS-301) says what the plan says, and what the fake IdP assumes."""

import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.fixtures.fake_idp import PERSONAS

ROOT = Path(__file__).resolve().parents[2]
REALM_FILE = ROOT / "deploy" / "keycloak" / "realm-keystone.json"
REALM: dict[str, Any] = json.loads(REALM_FILE.read_text())
PLACEHOLDER = re.compile(r"^\$\{[A-Z][A-Z0-9_]*\}$")
CONFIDENTIAL = ("support-agent", "ops-agent", "keystone-cli")


def group_paths(groups: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for group in groups:
        found[group["path"]] = group
        found |= group_paths(group.get("subGroups", []))
    return found


def clients() -> dict[str, dict[str, Any]]:
    return {c["clientId"]: c for c in REALM["clients"]}


def users() -> dict[str, dict[str, Any]]:
    return {u["username"]: u for u in REALM["users"]}


@pytest.mark.phase(3)
def test_the_realm_has_the_planned_groups_users_and_clients() -> None:
    assert REALM["realm"] == "keystone" and REALM["enabled"] is True
    assert set(group_paths(REALM["groups"])) == {
        "/tenants",
        "/tenants/acme",
        "/tenants/globex",
        "/support",
        "/operators",
        "/approvers",
        "/admins",
    }
    assert set(users()) == {"alice", "olivia", "lena", "bob", "root"}
    assert set(clients()) == {*CONFIDENTIAL, "console"}
    assert {r["name"] for r in REALM["roles"]["realm"]} == {"admin", "approver"}


@pytest.mark.phase(3)
def test_every_user_can_sign_in_without_further_steps() -> None:
    # Keycloak 26 answers a password grant with "Account is not fully set up" when the profile
    # lacks an email, a first or last name, or when a required action is pending.
    for name, user in users().items():
        assert user["id"] == name, "the token's sub should read as the user name"
        assert user["enabled"] is True and user["emailVerified"] is True
        assert user["requiredActions"] == []
        assert user["email"] and user["firstName"] and user["lastName"]
        [credential] = user["credentials"]
        assert credential["type"] == "password" and credential["temporary"] is False


@pytest.mark.phase(3)
def test_the_tenant_attribute_is_declared_in_the_user_profile() -> None:
    [provider] = REALM["components"]["org.keycloak.userprofile.UserProfileProvider"]
    [raw] = provider["config"]["kc.user.profile.config"]
    profile = json.loads(raw)

    declared = {attribute["name"] for attribute in profile["attributes"]}

    assert {"username", "email", "firstName", "lastName", "tenant"} <= declared
    assert {u["attributes"]["tenant"][0] for u in users().values()} == {"acme", "globex"}


@pytest.mark.phase(3)
def test_agent_clients_are_confidential_and_the_console_is_public_with_pkce() -> None:
    for name in CONFIDENTIAL:
        client = clients()[name]
        assert client["publicClient"] is False
        assert client["directAccessGrantsEnabled"] is True
        assert client["standardFlowEnabled"] is False
    console = clients()["console"]
    assert console["publicClient"] is True
    assert console["standardFlowEnabled"] is True
    assert console["directAccessGrantsEnabled"] is False
    assert console["redirectUris"] == ["http://localhost:5173/*"]
    assert console["attributes"]["pkce.code.challenge.method"] == "S256"


@pytest.mark.phase(6)
def test_the_console_can_sign_out_and_come_back_to_itself() -> None:
    """The console signs in with the redirect `http://localhost:5173/auth/callback` and signs out to
    `http://localhost:5173/signed-out`; it reads the tenant and the roles from the ID token."""
    console = clients()["console"]
    mappers = {m["name"]: m for m in console["protocolMappers"]}

    assert console["webOrigins"] == ["http://localhost:5173"]
    assert console["attributes"]["post.logout.redirect.uris"] == "http://localhost:5173/*"
    for name in ("tenant", "roles"):
        assert mappers[name]["config"]["id.token.claim"] == "true", name


@pytest.mark.phase(3)
def test_every_client_maps_audience_tenant_groups_and_roles() -> None:
    for name, client in clients().items():
        mappers = {m["name"]: m for m in client["protocolMappers"]}
        assert set(mappers) == {"keystone-audience", "tenant", "groups", "roles"}, name

        audience = mappers["keystone-audience"]
        assert audience["protocolMapper"] == "oidc-audience-mapper"
        assert audience["config"]["included.custom.audience"] == "keystone"
        assert audience["config"]["access.token.claim"] == "true"

        tenant = mappers["tenant"]["config"]
        assert (tenant["user.attribute"], tenant["claim.name"]) == ("tenant", "tenant")
        assert tenant["access.token.claim"] == "true"

        groups = mappers["groups"]["config"]
        assert groups["claim.name"] == "groups" and groups["full.path"] == "true"
        assert groups["access.token.claim"] == "true"

        roles = mappers["roles"]["config"]
        assert roles["claim.name"] == "roles" and roles["multivalued"] == "true"
        assert roles["access.token.claim"] == "true"


@pytest.mark.phase(3)
def test_no_password_or_secret_is_written_into_the_file() -> None:
    values = [c["secret"] for c in REALM["clients"] if "secret" in c]
    values += [cred["value"] for u in REALM["users"] for cred in u["credentials"]]

    assert len(values) == len(CONFIDENTIAL) + len(PERSONAS)
    assert all(PLACEHOLDER.match(value) for value in values), values


@pytest.mark.phase(3)
def test_the_fake_idp_personas_match_the_realm() -> None:
    groups_by_path = group_paths(REALM["groups"])
    group_roles = {path: set(group.get("realmRoles", [])) for path, group in groups_by_path.items()}
    for name, (tenant, groups, roles, _agent) in PERSONAS.items():
        user = users()[name]
        assert user["attributes"]["tenant"] == [tenant]
        assert set(user["groups"]) == set(groups)
        assert set().union(*(group_roles[g] for g in user["groups"])) == set(roles)
