"""KS-303: a bearer token becomes verified claims and a principal, or is refused with a reason."""

import base64
import json
import time
from typing import Any

import anyio
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from structlog.testing import capture_logs

from keystone.core.types import Principal
from keystone.identity.jwt import (
    ALLOWED_ALGORITHMS,
    AuthError,
    KeysUnavailable,
    Reason,
    TokenValidator,
)
from keystone.identity.principals import principal_from_claims
from keystone.settings import AgentConfig
from tests.fixtures.fake_idp import FakeIdp

AGENTS = {"support-agent": AgentConfig(trust="standard"), "ops-agent": AgentConfig(trust="high")}


class Clock:
    """A clock the test moves by hand, so the one-minute rule needs no sleeping."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def validator(idp: FakeIdp, **options: Any) -> TokenValidator:
    return TokenValidator(idp.issuer, "keystone", **options)


async def refused(check: TokenValidator, token: str) -> AuthError:
    with pytest.raises(AuthError) as raised:
        await check.validate(token)
    return raised.value


def forged(header: dict[str, Any], payload: dict[str, Any] | None = None) -> str:
    """A token with the given header and a made-up signature. Nothing here is signed."""

    def b64(value: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    claims = payload or {"sub": "alice", "exp": int(time.time()) + 300}
    return f"{b64(header)}.{b64(claims)}.{base64.urlsafe_b64encode(b'not a signature').decode()}"


@pytest.mark.phase(3)
async def test_valid_token_to_principal(fake_idp: FakeIdp) -> None:
    claims = await validator(fake_idp).validate(fake_idp.token_for("alice"))

    principal = principal_from_claims(claims, AGENTS)

    assert principal == Principal(
        tenant_id="acme",
        user_id="alice",
        groups=("support",),
        agent_id="support-agent",
        agent_trust="standard",
    )


@pytest.mark.phase(3)
async def test_the_decoder_is_given_exactly_the_algorithm_of_the_token(
    fake_idp: FakeIdp, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []
    real_decode = jwt.decode

    def spy(*args: Any, **kwargs: Any) -> dict[str, Any]:
        seen.append(list(kwargs["algorithms"]))
        decoded: dict[str, Any] = real_decode(*args, **kwargs)
        return decoded

    monkeypatch.setattr(jwt, "decode", spy)
    check = validator(fake_idp)

    await check.validate(fake_idp.make_token("alice", "acme"))
    await check.validate(fake_idp.make_token("alice", "acme", alg="ES256"))

    assert seen == [["RS256"], ["ES256"]]


@pytest.mark.phase(3)
async def test_a_valid_es256_token_is_accepted(fake_idp: FakeIdp) -> None:
    claims = await validator(fake_idp).validate(fake_idp.make_token("alice", "acme", alg="ES256"))

    assert claims["sub"] == "alice"


@pytest.mark.phase(3)
async def test_expired_rejected(fake_idp: FakeIdp) -> None:
    error = await refused(validator(fake_idp), fake_idp.make_token("alice", "acme", exp_in=-120))

    assert error.reason == "expired" and error.status == 401


@pytest.mark.phase(3)
async def test_leeway_forgives_a_small_clock_skew(fake_idp: FakeIdp) -> None:
    check = validator(fake_idp)

    skewed = fake_idp.make_token("alice", "acme", exp_in=-30)
    assert (await check.validate(skewed))["sub"] == "alice"
    error = await refused(check, fake_idp.make_token("alice", "acme", exp_in=-90))
    assert error.reason == "expired"


@pytest.mark.phase(3)
async def test_wrong_audience_rejected(fake_idp: FakeIdp) -> None:
    error = await refused(validator(fake_idp), fake_idp.make_token("alice", "acme", aud="other"))

    assert error.reason == "wrong_audience"


@pytest.mark.phase(3)
async def test_an_audience_list_that_contains_ours_is_accepted(fake_idp: FakeIdp) -> None:
    token = fake_idp.make_token("alice", "acme", aud=["account", "keystone"])

    assert (await validator(fake_idp).validate(token))["sub"] == "alice"


@pytest.mark.phase(3)
async def test_wrong_issuer_rejected(fake_idp: FakeIdp) -> None:
    token = fake_idp.make_token("alice", "acme", extra={"iss": "http://evil.test/realms/keystone"})

    assert (await refused(validator(fake_idp), token)).reason == "wrong_issuer"


@pytest.mark.phase(3)
async def test_alg_none_rejected(fake_idp: FakeIdp) -> None:
    error = await refused(validator(fake_idp), fake_idp.make_token("alice", "acme", alg="none"))

    assert error.reason == "alg_not_allowed"
    # Refused from the header alone: no key was looked up, so the IdP was never asked.
    assert (fake_idp.discovery_requests, fake_idp.jwks_requests) == (0, 0)


@pytest.mark.phase(3)
async def test_hs256_confusion_rejected(fake_idp: FakeIdp) -> None:
    # Signed with the RSA public key as the HMAC secret: it checks out for a verifier that lets
    # the token choose HS256 and hands it the key it holds for RS256.
    error = await refused(validator(fake_idp), fake_idp.make_token("alice", "acme", alg="HS256"))

    assert error.reason == "alg_not_allowed"
    assert (fake_idp.discovery_requests, fake_idp.jwks_requests) == (0, 0)


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    "alg",
    ["None", "NONE", "nOnE", "HS384", "HS512", "RS384", "RS512", "PS256", "ES384", "rs256", ""],
)
async def test_every_algorithm_outside_the_allowlist_is_refused_before_a_key_lookup(
    fake_idp: FakeIdp, alg: str
) -> None:
    error = await refused(validator(fake_idp), forged({"alg": alg, "typ": "JWT", "kid": "k"}))

    assert error.reason == "alg_not_allowed"
    assert (fake_idp.discovery_requests, fake_idp.jwks_requests) == (0, 0)


@pytest.mark.phase(3)
@pytest.mark.parametrize("alg", [None, 256, ["RS256"], {"alg": "RS256"}])
async def test_an_alg_that_is_not_a_string_is_refused(fake_idp: FakeIdp, alg: Any) -> None:
    error = await refused(validator(fake_idp), forged({"alg": alg, "kid": "k"}))

    assert error.reason == "alg_not_allowed"


@pytest.mark.phase(3)
async def test_a_header_without_an_alg_is_refused(fake_idp: FakeIdp) -> None:
    error = await refused(validator(fake_idp), forged({"typ": "JWT", "kid": "k"}))

    assert error.reason == "alg_not_allowed"


@pytest.mark.phase(3)
async def test_missing_tenant_rejected(fake_idp: FakeIdp) -> None:
    claims = await validator(fake_idp).validate(fake_idp.make_token("alice", None))

    with pytest.raises(AuthError) as raised:
        principal_from_claims(claims, AGENTS)

    assert raised.value.reason == "missing_tenant" and raised.value.status == 401


@pytest.mark.phase(3)
@pytest.mark.parametrize("claim", ["exp", "iat", "iss", "aud", "sub"])
async def test_each_of_exp_iat_iss_aud_and_sub_is_required(fake_idp: FakeIdp, claim: str) -> None:
    token = fake_idp.make_token("alice", "acme", extra={claim: None})

    error = await refused(validator(fake_idp), token)

    assert (error.reason, error.claim) == ("missing_claim", claim)


@pytest.mark.phase(3)
async def test_a_subject_that_is_not_a_string_is_refused(fake_idp: FakeIdp) -> None:
    token = fake_idp.make_token("alice", "acme", extra={"sub": 42})

    assert (await refused(validator(fake_idp), token)).reason == "invalid_claim"


@pytest.mark.phase(3)
async def test_a_token_that_is_not_valid_yet_is_refused(fake_idp: FakeIdp) -> None:
    later = int(time.time()) + 600
    check = validator(fake_idp)

    by_nbf = await refused(check, fake_idp.make_token("alice", "acme", extra={"nbf": later}))
    by_iat = await refused(check, fake_idp.make_token("alice", "acme", extra={"iat": later}))

    assert (by_nbf.reason, by_iat.reason) == ("not_yet_valid", "not_yet_valid")


@pytest.mark.phase(3)
async def test_a_changed_payload_is_refused(fake_idp: FakeIdp) -> None:
    head, body, signature = fake_idp.token_for("alice").split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["tenant"] = "globex"
    changed = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()

    error = await refused(validator(fake_idp), f"{head}.{changed}.{signature}")

    assert error.reason == "bad_signature"


@pytest.mark.phase(3)
async def test_a_signature_from_another_key_is_refused(fake_idp: FakeIdp) -> None:
    rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = jwt.decode(fake_idp.token_for("alice"), options={"verify_signature": False})
    kid = jwt.get_unverified_header(fake_idp.token_for("alice"))["kid"]
    token = jwt.encode(claims, rogue, algorithm="RS256", headers={"kid": kid})

    assert (await refused(validator(fake_idp), token)).reason == "bad_signature"


@pytest.mark.phase(3)
async def test_the_key_type_must_match_the_algorithm(fake_idp: FakeIdp) -> None:
    check = validator(fake_idp)
    rsa_kid = fake_idp.key_for("RS256").kid
    ec_kid = fake_idp.key_for("ES256").kid

    es_with_rsa_key = fake_idp.make_token("alice", "acme", alg="ES256", kid=rsa_kid)
    rs_with_ec_key = fake_idp.make_token("alice", "acme", alg="RS256", kid=ec_kid)

    assert (await refused(check, es_with_rsa_key)).reason == "key_type_mismatch"
    assert (await refused(check, rs_with_ec_key)).reason == "key_type_mismatch"


@pytest.mark.phase(3)
async def test_a_published_key_that_is_not_for_signing_is_not_used(fake_idp: FakeIdp) -> None:
    # Keycloak publishes an RSA key for encryption (use=enc) next to the signing key.
    enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = {**RSAAlgorithm.to_jwk(enc.public_key(), as_dict=True), "kid": "enc-key", "use": "enc"}
    fake_idp.extra_keys.append(jwk)
    claims = {"sub": "a", "exp": int(time.time()) + 300}
    token = jwt.encode(claims, enc, algorithm="RS256", headers={"kid": "enc-key"})

    assert (await refused(validator(fake_idp), token)).reason == "unknown_key"


@pytest.mark.phase(3)
@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
async def test_an_rsa_key_shorter_than_2048_bits_is_not_used(fake_idp: FakeIdp) -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    jwk = {**RSAAlgorithm.to_jwk(weak.public_key(), as_dict=True), "kid": "weak", "use": "sig"}
    fake_idp.extra_keys.append(jwk)
    claims = {"sub": "a", "exp": int(time.time()) + 300}
    token = jwt.encode(claims, weak, algorithm="RS256", headers={"kid": "weak"})

    assert (await refused(validator(fake_idp), token)).reason == "unknown_key"


@pytest.mark.phase(3)
async def test_a_token_without_a_kid_is_refused(fake_idp: FakeIdp) -> None:
    error = await refused(validator(fake_idp), fake_idp.make_token("alice", "acme", kid=""))

    assert error.reason == "missing_kid"


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    "fields",
    [
        {"jku": "http://evil.test/keys"},
        {"jwk": {"kty": "RSA", "n": "AQAB", "e": "AQAB"}},
        {"x5u": "http://evil.test/certificate"},
        {"crit": ["b64"], "b64": True},
    ],
)
async def test_header_fields_that_change_how_a_token_is_read_are_refused(
    fake_idp: FakeIdp, fields: dict[str, Any]
) -> None:
    token = fake_idp.make_token("alice", "acme", headers=fields)

    assert (await refused(validator(fake_idp), token)).reason == "unsupported_header"
    assert (fake_idp.discovery_requests, fake_idp.jwks_requests) == (0, 0)


@pytest.mark.phase(3)
async def test_a_critical_header_nobody_understands_is_refused(fake_idp: FakeIdp) -> None:
    token = fake_idp.make_token("alice", "acme", headers={"crit": ["exp"]})

    assert (await refused(validator(fake_idp), token)).reason == "malformed"


@pytest.mark.phase(3)
@pytest.mark.parametrize("token", ["", "abc", "a.b", "a.b.c", "....", "x" * 20_000])
async def test_text_that_is_not_a_token_is_malformed(fake_idp: FakeIdp, token: str) -> None:
    error = await refused(validator(fake_idp), token)

    assert error.reason == "malformed"
    assert (fake_idp.discovery_requests, fake_idp.jwks_requests) == (0, 0)


@pytest.mark.phase(3)
async def test_unknown_kid_refreshes_once(fake_idp: FakeIdp) -> None:
    clock = Clock()
    check = validator(fake_idp, clock=clock)
    await check.validate(fake_idp.token_for("alice"))  # loads the keys: one fetch
    assert fake_idp.jwks_requests == 1

    stranger = fake_idp.make_token("alice", "acme", kid="never-published")
    first = await refused(check, stranger)
    clock.now += 30
    second = await refused(check, stranger)
    third = await refused(check, stranger)

    assert [first.reason, second.reason, third.reason] == ["unknown_key"] * 3
    assert fake_idp.jwks_requests == 2  # one refresh for the first miss, none for the others
    clock.now += 31  # a minute after the refresh
    await refused(check, stranger)
    assert fake_idp.jwks_requests == 3


@pytest.mark.phase(3)
async def test_a_rotated_key_is_picked_up_by_one_refresh(fake_idp: FakeIdp) -> None:
    check = validator(fake_idp, clock=Clock())
    await check.validate(fake_idp.token_for("alice"))

    fake_idp.rotate()
    claims = await check.validate(fake_idp.token_for("alice"))

    assert claims["sub"] == "alice"
    assert fake_idp.jwks_requests == 2


@pytest.mark.phase(3)
async def test_a_token_signed_before_a_rotation_is_refused_afterwards(fake_idp: FakeIdp) -> None:
    check = validator(fake_idp, clock=Clock())
    old = fake_idp.token_for("alice")
    await check.validate(old)

    fake_idp.rotate()
    await check.validate(fake_idp.token_for("alice"))  # refreshes: the old key is dropped

    assert (await refused(check, old)).reason == "unknown_key"


@pytest.mark.phase(3)
async def test_a_withdrawn_key_stops_validating_when_the_set_reaches_its_max_age(
    fake_idp: FakeIdp,
) -> None:
    # The provider withdraws a key (a compromised one, say) and nobody sends a token under the
    # new kid: nothing misses the cache, so only the age of the set can bring the fetch.
    clock = Clock()
    check = validator(fake_idp, clock=clock, max_age_s=600)
    old = fake_idp.token_for("alice")
    await check.validate(old)
    fake_idp.rotate()

    clock.now += 599
    assert (await check.validate(old))["sub"] == "alice"
    assert fake_idp.jwks_requests == 1
    clock.now += 1
    error = await refused(check, old)

    assert error.reason == "unknown_key"
    assert fake_idp.jwks_requests == 2


@pytest.mark.phase(3)
async def test_an_aged_set_is_kept_while_the_idp_is_down(fake_idp: FakeIdp) -> None:
    clock = Clock()
    check = validator(fake_idp, clock=clock, max_age_s=600)
    token = fake_idp.token_for("alice")
    await check.validate(token)
    fake_idp.jwks_status = 503
    clock.now += 600

    assert (await check.validate(token))["sub"] == "alice"
    assert (await check.validate(token))["sub"] == "alice"
    assert fake_idp.jwks_requests == 2  # one try, not one per request
    clock.now += 60
    assert (await check.validate(token))["sub"] == "alice"
    assert fake_idp.jwks_requests == 3  # and again a minute later


@pytest.mark.phase(3)
async def test_a_shorter_cache_control_max_age_is_honoured(fake_idp: FakeIdp) -> None:
    fake_idp.jwks_cache_control = "public, max-age=120, must-revalidate"
    clock = Clock()
    check = validator(fake_idp, clock=clock)
    old = fake_idp.token_for("alice")
    await check.validate(old)
    fake_idp.rotate()

    clock.now += 119
    assert (await check.validate(old))["sub"] == "alice"
    clock.now += 1
    assert (await refused(check, old)).reason == "unknown_key"
    assert fake_idp.jwks_requests == 2


@pytest.mark.phase(3)
async def test_a_cache_control_that_forbids_caching_means_a_fetch_a_minute_at_most(
    fake_idp: FakeIdp,
) -> None:
    fake_idp.jwks_cache_control = "no-store, max-age=0"
    clock = Clock()
    check = validator(fake_idp, clock=clock)
    token = fake_idp.token_for("alice")

    for _ in range(5):
        await check.validate(token)
    assert fake_idp.jwks_requests == 1
    clock.now += 60
    await check.validate(token)
    assert fake_idp.jwks_requests == 2


@pytest.mark.phase(3)
async def test_many_requests_with_a_new_kid_cause_one_refresh(fake_idp: FakeIdp) -> None:
    check = validator(fake_idp, clock=Clock())
    await check.validate(fake_idp.token_for("alice"))
    fake_idp.rotate()
    token = fake_idp.token_for("alice")
    results: list[str] = []

    async def one() -> None:
        results.append((await check.validate(token))["sub"])

    async with anyio.create_task_group() as group:
        for _ in range(25):
            group.start_soon(one)

    assert results == ["alice"] * 25
    assert fake_idp.jwks_requests == 2


@pytest.mark.phase(3)
async def test_cached_keys_keep_working_while_the_idp_is_down(fake_idp: FakeIdp) -> None:
    check = validator(fake_idp)
    await check.validate(fake_idp.token_for("alice"))
    fake_idp.jwks_status = 503

    claims = await check.validate(fake_idp.token_for("bob"))

    assert claims["sub"] == "bob"
    assert fake_idp.jwks_requests == 1


# A published key Keystone never uses: EC, but on P-384.
P384_JWK = {
    **ECAlgorithm.to_jwk(ec.generate_private_key(ec.SECP384R1()).public_key(), as_dict=True),
    "kid": "p384",
    "use": "sig",
}


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    "document",
    [{"keys": []}, {"error": "starting"}, {"keys": [P384_JWK]}],
    ids=["no keys", "no keys field", "no usable key"],
)
async def test_a_jwks_answer_without_a_usable_key_keeps_the_cached_keys(
    fake_idp: FakeIdp, document: dict[str, Any]
) -> None:
    # A provider that is restarting can answer 200 with an empty set for a moment. That must not
    # empty the cache: every caller would be refused until the next refresh is allowed.
    check = validator(fake_idp, clock=Clock())
    token = fake_idp.token_for("alice")
    await check.validate(token)
    fake_idp.jwks_document = document

    with capture_logs() as logs:
        await refused(check, fake_idp.make_token("alice", "acme", kid="never-published"))

    assert (await check.validate(token))["sub"] == "alice"
    assert fake_idp.jwks_requests == 2
    assert "jwks_without_usable_keys" in [entry["event"] for entry in logs]


@pytest.mark.phase(3)
async def test_a_provider_that_publishes_no_usable_key_is_keys_unavailable(
    fake_idp: FakeIdp,
) -> None:
    clock = Clock()
    check = validator(fake_idp, clock=clock)
    fake_idp.jwks_document = {"keys": []}
    token = fake_idp.token_for("alice")

    error = await refused(check, token)

    assert isinstance(error, KeysUnavailable)
    fake_idp.jwks_document = None
    clock.now += 3
    assert (await check.validate(token))["sub"] == "alice"


@pytest.mark.phase(3)
async def test_an_idp_that_cannot_be_asked_is_keys_unavailable(fake_idp: FakeIdp) -> None:
    fake_idp.jwks_status = 500
    token = fake_idp.token_for("alice")

    error = await refused(validator(fake_idp), token)

    assert isinstance(error, KeysUnavailable)
    assert (error.reason, error.status) == (Reason.KEYS_UNAVAILABLE, 503)


@pytest.mark.phase(3)
async def test_a_jwks_fetch_that_is_too_slow_gives_up(fake_idp: FakeIdp) -> None:
    fake_idp.jwks_delay_s = 3.0
    started = time.monotonic()

    error = await refused(validator(fake_idp, timeout_s=0.3), fake_idp.token_for("alice"))

    assert error.reason == "keys_unavailable"
    assert time.monotonic() - started < 2.0


@pytest.mark.phase(3)
async def test_the_max_age_defaults_to_ten_minutes(fake_idp: FakeIdp) -> None:
    assert validator(fake_idp).max_age_s == 600.0


@pytest.mark.phase(3)
async def test_the_timeout_defaults_to_three_seconds(fake_idp: FakeIdp) -> None:
    assert validator(fake_idp).timeout_s == 3.0


@pytest.mark.phase(3)
async def test_a_down_idp_is_retried_soon_but_not_on_every_request(fake_idp: FakeIdp) -> None:
    clock = Clock()
    check = validator(fake_idp, clock=clock)
    fake_idp.jwks_status = 500
    token = fake_idp.token_for("alice")

    await refused(check, token)
    await refused(check, token)  # inside the retry interval: no new fetch
    assert fake_idp.jwks_requests == 1
    fake_idp.jwks_status = 200
    clock.now += 3

    assert (await check.validate(token))["sub"] == "alice"


@pytest.mark.phase(3)
async def test_a_discovery_document_for_another_issuer_is_refused(fake_idp: FakeIdp) -> None:
    fake_idp.discovery_issuer = "http://other.test/realms/keystone"

    error = await refused(validator(fake_idp), fake_idp.token_for("alice"))

    assert error.reason == "keys_unavailable"
    assert fake_idp.jwks_requests == 0


@pytest.mark.phase(3)
async def test_the_discovery_url_can_differ_from_the_issuer(fake_idp: FakeIdp) -> None:
    # Compose: tokens name http://localhost:8180 as the issuer, and Keystone fetches the keys from
    # http://keycloak:8080. Here the issuer is an address nothing listens on.
    frontend = "http://frontend.test/realms/keystone"
    fake_idp.discovery_issuer = frontend
    check = TokenValidator(frontend, "keystone", discovery_url=fake_idp.discovery_url)

    claims = await check.validate(fake_idp.make_token("alice", "acme", extra={"iss": frontend}))

    assert claims["iss"] == frontend
    wrong = fake_idp.make_token("alice", "acme")  # issued for the other address
    assert (await refused(check, wrong)).reason == "wrong_issuer"


@pytest.mark.phase(3)
async def test_a_failed_token_is_never_logged(fake_idp: FakeIdp) -> None:
    token = fake_idp.make_token("alice", "acme", exp_in=-300)
    with capture_logs() as logs:
        await refused(validator(fake_idp), token)
        fake_idp.jwks_status = 500
        await refused(validator(fake_idp), fake_idp.make_token("alice", "acme", kid="x"))

    signature = token.split(".")[2]
    assert token not in json.dumps(logs, default=str)
    assert signature not in json.dumps(logs, default=str)


@pytest.mark.phase(3)
def test_the_allowlist_is_rs256_and_es256_only() -> None:
    assert ALLOWED_ALGORITHMS == ("RS256", "ES256")
