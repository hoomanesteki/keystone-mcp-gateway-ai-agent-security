"""KS-301 against the real thing: the Keycloak container from `make up`, with the realm imported."""

import json
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy" / "docker-compose.yml")]
KEYCLOAK = f"http://localhost:{os.environ.get('KEYCLOAK_PORT', '8180')}"
REALM_URL = f"{KEYCLOAK}/realms/keystone"

pytestmark = [pytest.mark.phase(3), pytest.mark.e2e, pytest.mark.docker]


@pytest.fixture(scope="module")
def stack() -> Iterator[None]:
    # `up --wait` is idempotent, and --build picks up source changes.
    subprocess.run([*COMPOSE, "up", "-d", "--build", "--wait"], check=True, timeout=900)
    yield


def get_token(user: str, client: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "get_token.sh"), user, client],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**os.environ, **(env or {})},
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def verified_claims(token: str) -> dict[str, Any]:
    """Check the signature against Keycloak's published keys, then return the claims."""
    keys = jwt.PyJWKClient(f"{REALM_URL}/protocol/openid-connect/certs", timeout=10)
    signing_key = keys.get_signing_key_from_jwt(token)
    claims: dict[str, Any] = jwt.decode(
        token, signing_key.key, algorithms=["RS256"], audience="keystone", issuer=REALM_URL
    )
    return claims


def test_token_has_expected_claims(stack: None) -> None:
    claims = verified_claims(get_token("alice", "support-agent"))

    assert "keystone" in ([claims["aud"]] if isinstance(claims["aud"], str) else claims["aud"])
    assert claims["tenant"] == "acme"
    assert claims["azp"] == "support-agent"
    assert claims["sub"] == "alice"
    assert claims["iss"] == REALM_URL
    assert set(claims["groups"]) == {"/tenants/acme", "/support"}


@pytest.mark.parametrize(
    ("user", "client", "tenant", "groups", "roles"),
    [
        ("olivia", "ops-agent", "acme", {"/tenants/acme", "/operators"}, set()),
        ("lena", "keystone-cli", "acme", {"/tenants/acme", "/approvers"}, {"approver"}),
        ("bob", "support-agent", "globex", {"/tenants/globex"}, set()),
        ("root", "ops-agent", "acme", {"/tenants/acme", "/admins"}, {"admin"}),
    ],
)
def test_every_user_gets_their_tenant_groups_and_roles(
    stack: None, user: str, client: str, tenant: str, groups: set[str], roles: set[str]
) -> None:
    claims = verified_claims(get_token(user, client))

    assert (claims["sub"], claims["azp"], claims["tenant"]) == (user, client, tenant)
    assert set(claims["groups"]) == groups
    assert set(claims.get("roles", [])) == roles
    assert set(claims.get("realm_access", {}).get("roles", [])) == roles


def test_a_wrong_password_gets_no_token(stack: None) -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "get_token.sh"), "alice", "support-agent"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**os.environ, "ALICE_PASSWORD": "not-the-password"},
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "no token" in result.stderr


def test_the_issuer_is_the_same_inside_and_outside_the_network(stack: None) -> None:
    # Keystone fetches the discovery document and the keys from http://keycloak:8080, but tokens
    # fetched from the host name http://localhost:8180 as their issuer.
    script = (
        "import json, urllib.request as u; "
        "d = json.load(u.urlopen('http://keycloak:8080/realms/keystone/"
        ".well-known/openid-configuration', timeout=5)); print(json.dumps(d))"
    )
    inside = subprocess.run(
        [*COMPOSE, "exec", "-T", "keystone", "python", "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    document = json.loads(inside)
    outside = httpx.get(f"{REALM_URL}/.well-known/openid-configuration", timeout=10).json()

    assert document["issuer"] == outside["issuer"] == REALM_URL
    assert document["jwks_uri"].startswith("http://keycloak:8080/")
    assert outside["jwks_uri"].startswith(KEYCLOAK)


def admin_clients() -> dict[str, dict[str, Any]]:
    token = httpx.post(
        f"{KEYCLOAK}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
        },
        timeout=10,
    ).json()["access_token"]
    response = httpx.get(
        f"{KEYCLOAK}/admin/realms/keystone/clients",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    response.raise_for_status()
    return {c["clientId"]: c for c in response.json()}


def test_keycloak_accepted_the_client_settings_of_the_realm_file(stack: None) -> None:
    clients = admin_clients()

    console = clients["console"]
    assert console["publicClient"] is True
    assert console["redirectUris"] == ["http://localhost:5173/*"]
    assert console["attributes"]["pkce.code.challenge.method"] == "S256"
    for name in ("support-agent", "ops-agent", "keystone-cli"):
        assert clients[name]["publicClient"] is False
        assert clients[name]["directAccessGrantsEnabled"] is True
