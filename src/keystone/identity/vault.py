"""The credential vault (KS-305): the secrets Keystone sends to upstreams, encrypted at rest.

An agent never holds an upstream credential, and neither does the config file. A credential is a
set of HTTP headers (usually one, `X-Api-Key`) stored encrypted in Postgres with Fernet under the
master keys from `KEYSTONE_MASTER_KEYS`. The first key encrypts and every key decrypts, so a key
is rotated by putting a new one first, running `keystone cred rotate-keys`, and then removing the
old one.

What the vault hands out is `SecretStr` values. Each value it decrypts is also registered with the
log scrubber (keystone.logging), so that if it ever reaches a log line, by way of an exception
message for one, it is replaced there.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from pydantic import SecretStr

from keystone.core.errors import Code, Reject
from keystone.logging import register_secret

HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
MAX_VALUE_CHARS = 4096
# Headers the HTTP layer or the MCP transport owns. A credential that named one would break the
# request or the session instead of authenticating it.
RESERVED_HEADERS = frozenset(
    {
        "accept",
        "connection",
        "content-length",
        "content-type",
        "host",
        "mcp-protocol-version",
        "mcp-session-id",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
# Fingerprints (key_id) of keys that are published in this repository. A deployment with env=prod
# refuses them: a key that anyone can read in .env.example protects nothing.
PUBLISHED_KEY_IDS = frozenset({"a5bdf0770eeb"})
UNDECRYPTABLE = "a stored credential cannot be decrypted with any master key"


class VaultError(Exception):
    """A problem with the keys or the stored data. The message never holds a secret."""


class UnknownUpstream(VaultError):
    """A credential was set for an upstream that is not registered."""


def key_id(key: str) -> str:
    """A short fingerprint that names a master key without revealing it."""
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def check_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """The headers of a credential, if they are fit to send. Raises ValueError otherwise."""
    if not headers:
        raise ValueError("a credential needs at least one header")
    clean: dict[str, str] = {}
    for name, value in headers.items():
        if not HEADER_NAME.fullmatch(name):
            raise ValueError(f"{name!r} is not a usable header name")
        if name.lower() in RESERVED_HEADERS:
            raise ValueError(f"{name} is set by the HTTP layer and cannot be a credential")
        if not value or len(value) > MAX_VALUE_CHARS:
            raise ValueError(f"the value of {name} must be 1 to {MAX_VALUE_CHARS} characters")
        if not value.isascii() or not value.isprintable():
            raise ValueError(f"the value of {name} must be printable ASCII on one line")
        if name.lower() in {existing.lower() for existing in clean}:
            raise ValueError(f"{name} is given twice")
        clean[name] = value
    return clean


class Cipher:
    """Fernet under the master keys: the first encrypts, all of them decrypt."""

    def __init__(self, master_keys: str | SecretStr, *, refuse_published: bool = False) -> None:
        raw = master_keys.get_secret_value() if isinstance(master_keys, SecretStr) else master_keys
        entries = [part.strip() for part in raw.split(",")]
        if not any(entries):
            raise VaultError("KEYSTONE_MASTER_KEYS is empty")
        fernets: list[Fernet] = []
        self._ids: list[str] = []
        for number, entry in enumerate(entries, start=1):
            if not entry:
                raise VaultError(f"KEYSTONE_MASTER_KEYS has an empty entry at position {number}")
            try:
                fernets.append(Fernet(entry.encode()))
            except (ValueError, TypeError):
                raise VaultError(
                    f"entry {number} of KEYSTONE_MASTER_KEYS is not a Fernet key"
                ) from None
            self._ids.append(key_id(entry))
        if refuse_published and PUBLISHED_KEY_IDS.intersection(self._ids):
            raise VaultError(
                "KEYSTONE_MASTER_KEYS holds the key published in .env.example; make your own"
            )
        self._fernet = MultiFernet(fernets)
        self.primary_id = self._ids[0]

    def encrypt(self, headers: Mapping[str, str]) -> tuple[bytes, str]:
        payload = json.dumps(dict(sorted(headers.items())), separators=(",", ":")).encode()
        return self._fernet.encrypt(payload), self.primary_id

    def decrypt(self, ciphertext: bytes) -> dict[str, str]:
        try:
            payload = json.loads(self._fernet.decrypt(ciphertext))
        except InvalidToken:
            raise VaultError(UNDECRYPTABLE) from None
        except ValueError:
            raise VaultError("a stored credential is not what the vault wrote") from None
        if not isinstance(payload, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in payload.items()
        ):
            raise VaultError("a stored credential is not what the vault wrote")
        for value in payload.values():
            register_secret(value)
        return payload

    def rotate(self, ciphertext: bytes) -> tuple[bytes, str]:
        """The same credential encrypted under the first key."""
        try:
            return self._fernet.rotate(ciphertext), self.primary_id
        except InvalidToken:
            raise VaultError(UNDECRYPTABLE) from None


@dataclass(frozen=True)
class StoredCredential:
    ciphertext: bytes
    key_id: str


@dataclass(frozen=True)
class Lookup:
    """What the store knows about one upstream and one caller."""

    mode: str  # the upstream's credential_mode: none, static or per_user
    static: StoredCredential | None
    per_user: StoredCredential | None


@dataclass(frozen=True)
class CredentialInfo:
    """Metadata about a stored credential. Nothing here lets anyone read it."""

    tenant_id: str
    upstream_id: str
    user_id: str | None
    key_id: str
    created_at: datetime
    rotated_at: datetime | None


class CredentialStore(Protocol):
    async def lookup(
        self, tenant_id: str, upstream_id: str, user_id: str | None
    ) -> Lookup | None: ...

    async def put(
        self,
        tenant_id: str,
        upstream_id: str,
        user_id: str | None,
        ciphertext: bytes,
        key_id: str,
    ) -> None: ...

    async def infos(self) -> list[CredentialInfo]: ...

    async def rows(self) -> list[tuple[str, bytes, str]]: ...

    async def replace(self, row_id: str, old: bytes, new: bytes, key_id: str) -> bool: ...


@dataclass
class Rotation:
    rotated: int = 0
    unchanged: int = 0
    failed: list[str] = field(default_factory=list)


class Vault:
    def __init__(self, cipher: Cipher, store: CredentialStore) -> None:
        self._cipher = cipher
        self._store = store

    async def set(
        self,
        tenant_id: str,
        upstream_id: str,
        headers: Mapping[str, str],
        user_id: str | None = None,
    ) -> None:
        """Store the credential of an upstream, for one user or (without `user_id`) for all.
        It replaces what was there. Raises ValueError for headers that cannot be sent and
        UnknownUpstream for an upstream that is not registered."""
        clean = check_headers(headers)
        for value in clean.values():
            register_secret(value)
        ciphertext, kid = self._cipher.encrypt(clean)
        await self._store.put(tenant_id, upstream_id, user_id, ciphertext, kid)

    async def seed(self, tenant_id: str, upstream_id: str, headers: Mapping[str, str]) -> bool:
        """Make these the upstream's static credential, unless they already are, and under the
        first master key. This is how a credential given in the environment reaches the vault at
        startup: through the same code as `cred set`. Returns True when it wrote."""
        clean = check_headers(headers)
        found = await self._store.lookup(tenant_id, upstream_id, None)
        if found is None:
            raise UnknownUpstream(f"there is no upstream {upstream_id!r}")
        if found.static is not None and found.static.key_id == self._cipher.primary_id:
            try:
                if self._cipher.decrypt(found.static.ciphertext) == clean:
                    return False
            except VaultError:
                pass  # unreadable, so it is replaced
        await self.set(tenant_id, upstream_id, clean)
        return True

    async def headers_for(
        self, tenant_id: str, upstream_id: str, user_id: str | None
    ) -> dict[str, SecretStr]:
        """The headers to send for this caller, by the upstream's credential mode: none sends
        nothing, static sends the upstream's own credential, per_user sends the user's and
        refuses the call when there is none."""
        found = await self._store.lookup(tenant_id, upstream_id, user_id)
        if found is None:
            raise UnknownUpstream(f"there is no upstream {upstream_id!r}")
        if found.mode == "none":
            return {}
        if found.mode == "static":
            return self._open(found.static)
        if found.per_user is None:
            raise Reject(Code.DENIED, f"no credential for this user on {upstream_id}")
        return self._open(found.per_user)

    async def service_headers(self, tenant_id: str, upstream_id: str) -> dict[str, SecretStr]:
        """The upstream's own credential, for the calls Keystone makes for itself: reading the
        tool list and probing health. Nothing if it has none."""
        found = await self._store.lookup(tenant_id, upstream_id, None)
        if found is None or found.mode == "none":
            return {}
        return self._open(found.static)

    async def rotate_keys(self) -> Rotation:
        """Re-encrypt every credential under the first master key."""
        report = Rotation()
        for row_id, ciphertext, kid in await self._store.rows():
            if kid == self._cipher.primary_id:
                report.unchanged += 1
                continue
            try:
                renewed, new_kid = self._cipher.rotate(ciphertext)
            except VaultError:
                report.failed.append(row_id)
                continue
            if await self._store.replace(row_id, ciphertext, renewed, new_kid):
                report.rotated += 1
            else:
                report.unchanged += 1  # replaced by `cred set` meanwhile, under the first key
        return report

    async def infos(self) -> list[CredentialInfo]:
        return await self._store.infos()

    def _open(self, stored: StoredCredential | None) -> dict[str, SecretStr]:
        if stored is None:
            return {}
        opened = self._cipher.decrypt(stored.ciphertext)
        return {name: SecretStr(value) for name, value in opened.items()}
