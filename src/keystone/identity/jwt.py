"""Turn a bearer token into verified claims (KS-303).

Read `TokenValidator.validate` first. The order of its checks is what keeps a forged token out:

1. The header is read without verifying anything, and a token whose `alg` is not RS256 or ES256 is
   refused there, before a key is looked up. `none` and the HMAC algorithms never get further, so
   the classic attacks (an unsigned token, or an HS256 token signed with the public key as the
   secret) have nothing to work on.
2. The `kid` picks one key from the identity provider's published set.
3. That key must be the kind the algorithm needs: an RSA key of 2048 bits or more for RS256, an
   EC P-256 key for ES256.
4. PyJWT verifies the signature and the claims, and is given exactly the one algorithm from step 1.

The identity provider's keys are fetched with a 3 s timeout and cached. A token with an unknown
`kid` may refresh them, at most once a minute, so that a rotation is picked up and a flood of
made-up key ids cannot turn into a flood of requests to the identity provider. The set is also
fetched again once it is older than `max_age_s` (10 minutes, or a shorter `Cache-Control` max-age),
so that a key the provider withdraws stops being trusted even when no request ever misses the cache.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import anyio
import httpx2
import jwt
import structlog
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

log = structlog.get_logger()

ALLOWED_ALGORITHMS = ("RS256", "ES256")
REQUIRED_CLAIMS = ("exp", "iat", "iss", "aud", "sub")
# Header fields that change which key is used or how the token is read. None is needed here.
UNSAFE_HEADER_FIELDS = frozenset({"jku", "jwk", "x5u", "crit", "b64"})
MIN_RSA_BITS = 2048

JWKS_TIMEOUT_S = 3.0
JWKS_REFRESH_INTERVAL_S = 60.0
# How long a fetched set is trusted before it is fetched again, whatever the tokens name.
JWKS_MAX_AGE_S = 600.0
# With no keys at all, a failed fetch may be tried again this soon.
COLD_RETRY_INTERVAL_S = 2.0
MAX_TOKEN_CHARS = 16 * 1024
MAX_KID_CHARS = 256
CACHE_CONTROL_MAX_AGE = re.compile(r"\bmax-age=(\d+)", re.IGNORECASE)


class Reason(StrEnum):
    """Why a request was refused. Short, stable and safe to show to the caller and to log."""

    NO_CREDENTIALS = "no_credentials"
    MALFORMED = "malformed"
    ALG_NOT_ALLOWED = "alg_not_allowed"
    UNSUPPORTED_HEADER = "unsupported_header"
    MISSING_KID = "missing_kid"
    UNKNOWN_KEY = "unknown_key"
    KEY_TYPE_MISMATCH = "key_type_mismatch"
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    WRONG_AUDIENCE = "wrong_audience"
    WRONG_ISSUER = "wrong_issuer"
    MISSING_CLAIM = "missing_claim"
    INVALID_CLAIM = "invalid_claim"
    INVALID_TOKEN = "invalid_token"  # noqa: S105 - a reason code, not a token
    KEYS_UNAVAILABLE = "keys_unavailable"
    MISSING_TENANT = "missing_tenant"
    INVALID_TENANT = "invalid_tenant"
    UNKNOWN_TENANT = "unknown_tenant"
    MISSING_AGENT = "missing_agent"
    UNKNOWN_AGENT = "unknown_agent"


class AuthError(Exception):
    """The request cannot be tied to a principal. `status` is the HTTP status to answer with."""

    status = 401

    def __init__(self, reason: Reason, claim: str | None = None) -> None:
        super().__init__(reason.value)
        self.reason = reason
        # The claim that was missing or wrong, for MISSING_CLAIM and INVALID_CLAIM.
        self.claim = claim


class Forbidden(AuthError):
    """The token is sound but the caller may not use Keystone (an agent that is not known)."""

    status = 403


class KeysUnavailable(AuthError):
    """The identity provider's keys could not be fetched, so no token can be checked now."""

    status = 503

    def __init__(self) -> None:
        super().__init__(Reason.KEYS_UNAVAILABLE)


@dataclass(frozen=True)
class _Key:
    public: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
    alg: str | None  # the algorithm the published key names, if it names one


def _read_header(token: str) -> dict[str, Any]:
    if not token or len(token) > MAX_TOKEN_CHARS or token.count(".") != 2:
        raise AuthError(Reason.MALFORMED)
    try:
        return jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise AuthError(Reason.MALFORMED) from None


def _admit(jwk: object) -> tuple[str, _Key] | None:
    """The usable signing key in one entry of a JWKS, or None. A published key is skipped, not
    trusted with less care: an encryption key, a key for another algorithm, a private key (which
    should never be published), an RSA key under 2048 bits, an EC key on another curve."""
    if not isinstance(jwk, dict):
        return None
    kid, kty, alg = jwk.get("kid"), jwk.get("kty"), jwk.get("alg")
    if not isinstance(kid, str) or not kid or "d" in jwk or jwk.get("use", "sig") != "sig":
        return None
    if alg is not None and alg not in ALLOWED_ALGORITHMS:
        return None
    try:
        if kty == "RSA":
            rsa_key = RSAAlgorithm.from_jwk(jwk)
            if isinstance(rsa_key, rsa.RSAPublicKey) and rsa_key.key_size >= MIN_RSA_BITS:
                return kid, _Key(rsa_key, alg)
        elif kty == "EC":
            ec_key = ECAlgorithm.from_jwk(jwk)
            if isinstance(ec_key, ec.EllipticCurvePublicKey) and isinstance(
                ec_key.curve, ec.SECP256R1
            ):
                return kid, _Key(ec_key, alg)
    except (jwt.PyJWTError, ValueError, TypeError):
        return None
    return None


def _parse_jwks(document: object) -> dict[str, _Key]:
    entries = document.get("keys") if isinstance(document, dict) else None
    keys: dict[str, _Key] = {}
    for entry in entries if isinstance(entries, list) else []:
        admitted = _admit(entry)
        if admitted is not None:
            keys.setdefault(*admitted)
    return keys


def _advertised_max_age(cache_control: str | None) -> float | None:
    """The `max-age` of a Cache-Control header, in seconds, when it names one. `no-store` and
    `no-cache` say nothing about how long a key stays valid, so they are not read as zero."""
    match = CACHE_CONTROL_MAX_AGE.search(cache_control or "")
    return float(match.group(1)) if match else None


def check_key_type(alg: str, key: _Key) -> None:
    """The key must be the kind the algorithm needs. Raises KEY_TYPE_MISMATCH otherwise, so a
    token cannot be checked with a key of another family, whatever its `kid` points at."""
    public = key.public
    if alg == "RS256":
        fits = isinstance(public, rsa.RSAPublicKey)
    else:
        fits = isinstance(public, ec.EllipticCurvePublicKey) and isinstance(
            public.curve, ec.SECP256R1
        )
    if not fits or (key.alg is not None and key.alg != alg):
        raise AuthError(Reason.KEY_TYPE_MISMATCH)


class TokenValidator:
    def __init__(
        self,
        issuer: str,
        audience: str,
        leeway_s: float = 60.0,
        *,
        discovery_url: str | None = None,
        timeout_s: float = JWKS_TIMEOUT_S,
        refresh_interval_s: float = JWKS_REFRESH_INTERVAL_S,
        max_age_s: float = JWKS_MAX_AGE_S,
        retry_interval_s: float = COLD_RETRY_INTERVAL_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.leeway_s = leeway_s
        # Where to read the discovery document, when that differs from the issuer's own address.
        # In compose, tokens name http://localhost:8180 and Keystone asks http://keycloak:8080.
        self.discovery_url = (
            discovery_url or f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        )
        self.timeout_s = timeout_s
        self.max_age_s = max_age_s
        self._refresh_interval_s = refresh_interval_s
        self._retry_interval_s = retry_interval_s
        self._clock = clock
        self._jwks_uri: str | None = None
        self._keys: dict[str, _Key] = {}
        self._loaded = False
        self._fetched_at: float | None = None
        # `max_age_s`, or the shorter max-age the last JWKS answer advertised.
        self._age_limit_s = max_age_s
        self._last_cold_attempt: float | None = None
        self._last_refresh: float | None = None
        self._last_refresh_failed = False
        self._lock = anyio.Lock()

    async def validate(self, token: str) -> dict[str, Any]:
        """The claims of a token that is sound, or AuthError with the reason."""
        header = _read_header(token)
        alg = header.get("alg")
        # The allowlist comes first and uses only what the token says about itself. Nothing below
        # runs for `none`, an HMAC algorithm, an RSA-PSS or ES384 token, or a missing `alg`.
        if not isinstance(alg, str) or alg not in ALLOWED_ALGORITHMS:
            raise AuthError(Reason.ALG_NOT_ALLOWED)
        if not UNSAFE_HEADER_FIELDS.isdisjoint(header):
            raise AuthError(Reason.UNSUPPORTED_HEADER)
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > MAX_KID_CHARS:
            raise AuthError(Reason.MISSING_KID)

        key = await self._signing_key(kid)
        check_key_type(alg, key)
        return self._verify(token, alg, key)

    def _verify(self, token: str, alg: str, key: _Key) -> dict[str, Any]:
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key.public,
                algorithms=[alg],  # exactly the algorithm the allowlist let through
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway_s,
                options={
                    "require": list(REQUIRED_CLAIMS),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_sub": True,
                },
            )
        except jwt.ExpiredSignatureError:
            raise AuthError(Reason.EXPIRED) from None
        except (jwt.ImmatureSignatureError, jwt.InvalidIssuedAtError):
            raise AuthError(Reason.NOT_YET_VALID) from None
        except jwt.InvalidAudienceError:
            raise AuthError(Reason.WRONG_AUDIENCE) from None
        except jwt.InvalidIssuerError:
            raise AuthError(Reason.WRONG_ISSUER) from None
        except jwt.MissingRequiredClaimError as exc:
            raise AuthError(Reason.MISSING_CLAIM, exc.claim) from None
        except jwt.exceptions.InvalidSubjectError:
            raise AuthError(Reason.INVALID_CLAIM, "sub") from None
        except jwt.InvalidSignatureError:
            raise AuthError(Reason.BAD_SIGNATURE) from None
        except (jwt.InvalidKeyError, jwt.InvalidAlgorithmError):
            raise AuthError(Reason.KEY_TYPE_MISMATCH) from None
        except jwt.DecodeError:
            raise AuthError(Reason.MALFORMED) from None
        except jwt.InvalidTokenError:
            raise AuthError(Reason.INVALID_TOKEN) from None
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise AuthError(Reason.INVALID_CLAIM, "sub")
        return claims

    async def _signing_key(self, kid: str) -> _Key:
        if self._aged():
            await self._refresh(None)
        key = self._keys.get(kid)
        if key is None:
            await self._refresh(kid)
            key = self._keys.get(kid)
        if key is None:
            raise AuthError(Reason.UNKNOWN_KEY)
        return key

    def _aged(self) -> bool:
        """The set was fetched longer ago than its age limit."""
        fetched_at = self._fetched_at
        return fetched_at is not None and self._clock() - fetched_at >= self._age_limit_s

    async def _refresh(self, kid: str | None) -> None:
        """Fetch the keys, when that is allowed: for a kid that is not in the cache, or (kid None)
        because the set has reached its age limit.

        With no keys yet, the fetch may be repeated every `retry_interval_s`. With keys, a miss
        or the age may refresh them once per `refresh_interval_s`; the first fetch does not count
        against that, so the first rotation after startup is picked up at once. When the fetch for
        an aged set fails, the old set stays: a token under a cached key was not shown to be bad.
        """
        async with self._lock:
            # Another request may have refreshed them while this one waited for the lock.
            if (kid is None and not self._aged()) or (kid is not None and kid in self._keys):
                return
            now = self._clock()
            if not self._loaded:
                last = self._last_cold_attempt
                if last is not None and now - last < self._retry_interval_s:
                    raise KeysUnavailable
                self._last_cold_attempt = now
            else:
                last = self._last_refresh
                if last is not None and now - last < self._refresh_interval_s:
                    if self._last_refresh_failed and kid is not None:
                        raise KeysUnavailable
                    return
                self._last_refresh = now
            try:
                keys, advertised_max_age = await self._fetch()
            except KeysUnavailable:
                self._last_refresh_failed = True
                if kid is None:
                    return
                raise
            self._keys = keys
            self._last_refresh_failed = False
            self._loaded = True
            self._fetched_at = now
            # A shorter max-age from the provider is honoured, down to the refresh interval, so
            # that `max-age=0` means one fetch a minute and not one per request.
            self._age_limit_s = self.max_age_s
            if advertised_max_age is not None:
                self._age_limit_s = min(
                    self.max_age_s, max(advertised_max_age, self._refresh_interval_s)
                )

    async def _fetch(self) -> tuple[dict[str, _Key], float | None]:
        """The published keys and the max-age their answer advertised, if any."""
        try:
            async with httpx2.AsyncClient(
                timeout=httpx2.Timeout(self.timeout_s), follow_redirects=False
            ) as http:
                if self._jwks_uri is None:
                    self._jwks_uri = await self._discover(http)
                try:
                    response = await self._get(http, self._jwks_uri)
                    keys = _parse_jwks(_json_object(response))
                    if not keys:
                        # A 200 with no key Keystone can use (a provider that is starting up, or
                        # one that publishes only keys _admit skips) is a failed fetch, not a new
                        # set: taking it would refuse every caller until the next refresh.
                        log.warning("jwks_without_usable_keys")
                        raise KeysUnavailable
                    return keys, _advertised_max_age(response.headers.get("cache-control"))
                except Exception:
                    self._jwks_uri = None  # ask the discovery document again next time
                    raise
        except KeysUnavailable:
            raise
        except Exception as exc:
            # The text of the error can hold the address and nothing else, but log the type only.
            log.warning("jwks_fetch_failed", error=type(exc).__name__)
            raise KeysUnavailable from None

    async def _discover(self, http: httpx2.AsyncClient) -> str:
        document = _json_object(await self._get(http, self.discovery_url))
        if document.get("issuer") != self.issuer:
            # Talking to the wrong identity provider, or one configured for another address.
            log.error(
                "oidc_issuer_mismatch",
                configured=self.issuer,
                discovery_says=str(document.get("issuer"))[:200],
            )
            raise KeysUnavailable
        uri = document.get("jwks_uri")
        if not isinstance(uri, str) or not uri.startswith(("http://", "https://")):
            log.error("oidc_discovery_without_jwks_uri")
            raise KeysUnavailable
        return uri

    async def _get(self, http: httpx2.AsyncClient, url: str) -> httpx2.Response:
        with anyio.fail_after(self.timeout_s):
            response = await http.get(url)
        if response.status_code != 200:
            log.warning("oidc_fetch_refused", status=response.status_code)
            raise KeysUnavailable
        return response


def _json_object(response: httpx2.Response) -> dict[str, Any]:
    body = response.json()
    if not isinstance(body, dict):
        raise KeysUnavailable
    return body
