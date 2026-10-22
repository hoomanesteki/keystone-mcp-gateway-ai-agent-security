import base64
import hashlib
import hmac
import time
from typing import Any

import httpx
import jwt
import pytest

from tests.fixtures.fake_idp import AUDIENCE, PERSONAS, FakeIdp


def fetch_jwks(idp: FakeIdp) -> dict[str, Any]:
    body: dict[str, Any] = httpx.get(idp.jwks_url, timeout=5).json()
    return body


def verify(idp: FakeIdp, token: str, alg: str = "RS256") -> dict[str, Any]:
    """What a relying party does: find the key by kid in the served JWKS and verify with it."""
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next(k for k in fetch_jwks(idp)["keys"] if k["kid"] == kid)
    claims: dict[str, Any] = jwt.decode(
        token, jwt.PyJWK(jwk).key, algorithms=[alg], audience=AUDIENCE, issuer=idp.issuer
    )
    return claims


def unverified(token: str) -> dict[str, Any]:
    claims: dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
    return claims


@pytest.mark.phase(3)
def test_token_validates_against_jwks(fake_idp: FakeIdp) -> None:
    token = fake_idp.make_token("alice", "acme", groups=["/tenants/acme", "/support"])

    claims = verify(fake_idp, token)

    assert (claims["sub"], claims["tenant"], claims["azp"]) == ("alice", "acme", "support-agent")
    assert claims["groups"] == ["/tenants/acme", "/support"]
    assert claims["iss"] == fake_idp.issuer
    assert claims["aud"] == "keystone"
    assert claims["exp"] - claims["iat"] == 300


@pytest.mark.phase(3)
def test_the_discovery_document_points_at_the_jwks(fake_idp: FakeIdp) -> None:
    document = httpx.get(fake_idp.discovery_url, timeout=5).json()

    assert document["issuer"] == fake_idp.issuer
    assert document["jwks_uri"] == fake_idp.jwks_url
    assert fake_idp.issuer.endswith("/realms/keystone")


@pytest.mark.phase(3)
def test_an_es256_token_validates_with_the_ec_key(fake_idp: FakeIdp) -> None:
    token = fake_idp.make_token("alice", "acme", alg="ES256")

    claims = verify(fake_idp, token, alg="ES256")

    assert claims["sub"] == "alice"
    kinds = {key["kid"]: key["kty"] for key in fetch_jwks(fake_idp)["keys"]}
    assert sorted(kinds.values()) == ["EC", "RSA"]
    assert kinds[jwt.get_unverified_header(token)["kid"]] == "EC"


@pytest.mark.phase(3)
def test_rotate_swaps_the_key_id(fake_idp: FakeIdp) -> None:
    before = fake_idp.make_token("alice", "acme")
    old_kid = jwt.get_unverified_header(before)["kid"]

    fake_idp.rotate()
    after = fake_idp.make_token("alice", "acme")

    new_kid = jwt.get_unverified_header(after)["kid"]
    assert new_kid != old_kid
    assert old_kid not in {k["kid"] for k in fetch_jwks(fake_idp)["keys"]}
    assert verify(fake_idp, after)["sub"] == "alice"
    with pytest.raises(StopIteration):
        verify(fake_idp, before)  # the old kid is no longer in the JWKS


@pytest.mark.phase(3)
def test_options_change_one_claim_each(fake_idp: FakeIdp) -> None:
    token = fake_idp.make_token(
        "olivia",
        None,
        groups=["/operators"],
        azp="ops-agent",
        roles=["admin"],
        aud=["keystone", "account"],
        exp_in=-120,
        extra={"iat": None, "department": "ops"},
    )

    claims = unverified(token)

    assert "tenant" not in claims and "iat" not in claims
    assert claims["aud"] == ["keystone", "account"]
    assert (claims["roles"], claims["azp"], claims["department"]) == (["admin"], "ops-agent", "ops")
    assert claims["exp"] < time.time() - 100


@pytest.mark.phase(3)
def test_an_expired_token_fails_verification(fake_idp: FakeIdp) -> None:
    token = fake_idp.make_token("alice", "acme", exp_in=-30)

    with pytest.raises(jwt.ExpiredSignatureError):
        verify(fake_idp, token)


@pytest.mark.phase(3)
def test_a_token_can_leave_out_or_change_the_kid(fake_idp: FakeIdp) -> None:
    without = fake_idp.make_token("a", "acme", kid="")
    other = fake_idp.make_token("a", "acme", kid="other")

    assert "kid" not in jwt.get_unverified_header(without)
    assert jwt.get_unverified_header(other)["kid"] == "other"


@pytest.mark.phase(3)
def test_forged_tokens_are_well_formed_but_unsound(fake_idp: FakeIdp) -> None:
    unsigned = fake_idp.make_token("alice", "acme", alg="none")
    confused = fake_idp.make_token("alice", "acme", alg="HS256")

    assert jwt.get_unverified_header(unsigned)["alg"] == "none"
    assert unsigned.endswith(".") and unsigned.count(".") == 2
    assert jwt.get_unverified_header(confused)["alg"] == "HS256"
    # The HMAC secret is the RSA public key in PEM form: a verifier that lets HS256 in and hands
    # it the public key it holds for RS256 would accept this.
    head, body, signature = confused.split(".")
    expected = hmac.new(fake_idp.public_pem(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    assert base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)) == expected
    # PyJWT itself refuses to use a PEM public key as an HMAC secret.
    with pytest.raises(jwt.InvalidKeyError):
        jwt.decode(confused, fake_idp.public_pem(), algorithms=["HS256"], audience=AUDIENCE)


@pytest.mark.phase(3)
def test_requests_are_counted_and_an_outage_can_be_simulated(fake_idp: FakeIdp) -> None:
    httpx.get(fake_idp.discovery_url, timeout=5)
    httpx.get(fake_idp.jwks_url, timeout=5)
    fake_idp.jwks_status = 503
    down = httpx.get(fake_idp.jwks_url, timeout=5)

    assert (fake_idp.discovery_requests, fake_idp.jwks_requests) == (1, 2)
    assert down.status_code == 503


@pytest.mark.phase(3)
def test_a_persona_token_carries_what_keycloak_would_send(fake_idp: FakeIdp) -> None:
    bob = unverified(fake_idp.token_for("bob"))
    olivia = unverified(fake_idp.token_for("olivia"))
    lena = unverified(fake_idp.token_for("lena", agent="keystone-cli"))

    assert (bob["sub"], bob["tenant"], bob["groups"]) == ("bob", "globex", ["/tenants/globex"])
    assert bob["azp"] == "support-agent"
    assert (olivia["tenant"], olivia["groups"], olivia["azp"]) == (
        "acme",
        ["/tenants/acme", "/operators"],
        "ops-agent",
    )
    assert lena["roles"] == ["approver"]
    assert set(PERSONAS) == {"alice", "olivia", "lena", "bob", "root"}
