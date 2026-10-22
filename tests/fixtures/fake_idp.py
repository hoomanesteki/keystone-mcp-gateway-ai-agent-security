"""An OpenID provider in a background thread, for tests that need tokens but not Keycloak (KS-302).

It serves the discovery document and the JWKS on a random port, with the paths Keycloak uses, and
signs tokens with an RSA 2048 key and an EC P-256 key. `make_token` builds a valid token by
default and takes options that break it in one chosen way: an expired token, a wrong audience, a
missing claim, `alg=none`, and the classic HS256 forgery that signs with the RSA public key.

The first pair of keys is made once per test process (RSA generation takes about 0.1 s) and
shared by every instance. Each instance gives its keys new ids, and `rotate()` makes new keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any

import anyio
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from tests.fixtures.servers import ServerThread

AUDIENCE = "keystone"
REALM_PATH = "/realms/keystone"

# The users of deploy/keycloak/realm-keystone.json: tenant, groups (full paths, as Keycloak sends
# them), realm roles and the agent each normally signs in through. tests/unit/test_realm.py
# checks that this table and the realm file say the same.
PERSONAS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...], str]] = {
    "alice": ("acme", ("/tenants/acme", "/support"), (), "support-agent"),
    "olivia": ("acme", ("/tenants/acme", "/operators"), (), "ops-agent"),
    "lena": ("acme", ("/tenants/acme", "/approvers"), ("approver",), "keystone-cli"),
    "bob": ("globex", ("/tenants/globex",), (), "support-agent"),
    "root": ("acme", ("/tenants/acme", "/admins"), ("admin",), "ops-agent"),
}


@cache
def _first_keys() -> tuple[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        ec.generate_private_key(ec.SECP256R1()),
    )


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_b64(value: Mapping[str, Any]) -> str:
    return _b64(json.dumps(value, separators=(",", ":")).encode())


@dataclass(frozen=True)
class SigningKey:
    kid: str
    alg: str  # "RS256" or "ES256"
    private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

    def jwk(self) -> dict[str, Any]:
        public = self.private.public_key()
        if isinstance(public, rsa.RSAPublicKey):
            body = RSAAlgorithm.to_jwk(public, as_dict=True)
        else:
            assert isinstance(public, ec.EllipticCurvePublicKey)
            body = ECAlgorithm.to_jwk(public, as_dict=True)
        return {**body, "kid": self.kid, "alg": self.alg, "use": "sig"}

    def public_pem(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )


class FakeIdp:
    """The provider. Use the `fake_idp` fixture, or `FakeIdp()` and `stop()`."""

    def __init__(self) -> None:
        self.audience = AUDIENCE
        # Counters and switches for tests about caching and outages.
        self.discovery_requests = 0
        self.jwks_requests = 0
        self.jwks_status = 200
        self.jwks_delay_s = 0.0
        self.discovery_issuer: str | None = None  # what the document claims, if not the issuer
        self._keys: dict[str, SigningKey] = {}
        rsa_key, ec_key = _first_keys()
        self._install(rsa_key, ec_key)
        routes = [
            Route(f"{REALM_PATH}/.well-known/openid-configuration", self._discovery),
            Route(f"{REALM_PATH}/protocol/openid-connect/certs", self._jwks),
        ]
        self._thread = ServerThread(Starlette(routes=routes)).start()

    @property
    def issuer(self) -> str:
        return f"{self._thread.url}{REALM_PATH}"

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"

    def stop(self) -> None:
        self._thread.stop()

    def jwks(self) -> dict[str, Any]:
        return {"keys": [key.jwk() for key in self._keys.values()]}

    def key_for(self, alg: str) -> SigningKey:
        """The current signing key for an algorithm: the RSA key for RS256 (and the other RSA
        algorithms), the EC key for ES256."""
        return self._keys["ES256" if alg == "ES256" else "RS256"]

    def public_pem(self, alg: str = "RS256") -> bytes:
        return self.key_for(alg).public_pem()

    def rotate(self) -> None:
        """Replace both keys with new ones. Tokens signed before now carry a kid that the JWKS no
        longer lists."""
        self._install(
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            ec.generate_private_key(ec.SECP256R1()),
        )

    def _install(self, rsa_key: rsa.RSAPrivateKey, ec_key: ec.EllipticCurvePrivateKey) -> None:
        self._keys = {
            "RS256": SigningKey(secrets.token_hex(8), "RS256", rsa_key),
            "ES256": SigningKey(secrets.token_hex(8), "ES256", ec_key),
        }

    def make_token(
        self,
        sub: str,
        tenant: str | None,
        groups: Iterable[str] = (),
        azp: str | None = "support-agent",
        roles: Iterable[str] = (),
        aud: str | Iterable[str] = AUDIENCE,
        exp_in: float = 300,
        alg: str = "RS256",
        kid: str | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> str:
        """A signed token. `tenant=None` and `azp=None` leave those claims out. `extra` is merged
        over the claims last, and a value of None removes the claim, so any claim can be changed
        or dropped. `kid=""` leaves the kid out of the header. `alg` may also be "none" (no
        signature) or "HS256" (signed with the RSA public key as the HMAC secret, the key
        confusion forgery)."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": sub,
            "aud": aud if isinstance(aud, str) else list(aud),
            "iat": now,
            "exp": int(now + exp_in),
            "jti": secrets.token_hex(8),
            "typ": "Bearer",
            "groups": list(groups),
            "roles": list(roles),
        }
        if tenant is not None:
            claims["tenant"] = tenant
        if azp is not None:
            claims["azp"] = azp
        for name, value in (extra or {}).items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value

        key = self.key_for(alg)
        header_kid = key.kid if kid is None else kid
        headers = {"kid": header_kid} if header_kid else {}
        if alg == "none":
            header = {"alg": "none", "typ": "JWT", **headers}
            return f"{_json_b64(header)}.{_json_b64(claims)}."
        if alg.startswith("HS"):
            header = {"alg": alg, "typ": "JWT", **headers}
            signing_input = f"{_json_b64(header)}.{_json_b64(claims)}".encode("ascii")
            digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[
                alg
            ]
            mac = hmac.new(key.public_pem(), signing_input, digest).digest()
            return f"{signing_input.decode('ascii')}.{_b64(mac)}"
        return jwt.encode(claims, key.private, algorithm=alg, headers=headers)

    def token_for(self, user: str, agent: str | None = None, **options: Any) -> str:
        """A token for one of the realm's users, as Keycloak would issue it. `agent` is the client
        the user signs in through (default: the persona's usual one)."""
        tenant, groups, roles, usual_agent = PERSONAS[user]
        return self.make_token(
            user, tenant, groups=groups, azp=agent or usual_agent, roles=roles, **options
        )

    async def _discovery(self, request: Request) -> Response:
        self.discovery_requests += 1
        return JSONResponse(
            {
                "issuer": self.discovery_issuer or self.issuer,
                "jwks_uri": self.jwks_url,
                "authorization_endpoint": f"{self.issuer}/protocol/openid-connect/auth",
                "token_endpoint": f"{self.issuer}/protocol/openid-connect/token",
                "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            }
        )

    async def _jwks(self, request: Request) -> Response:
        self.jwks_requests += 1
        if self.jwks_delay_s:
            await anyio.sleep(self.jwks_delay_s)
        if self.jwks_status != 200:
            return Response(status_code=self.jwks_status)
        return JSONResponse(self.jwks())


@pytest.fixture
def fake_idp() -> Iterator[FakeIdp]:
    idp = FakeIdp()
    try:
        yield idp
    finally:
        idp.stop()
