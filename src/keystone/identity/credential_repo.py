"""The `credentials` table behind the vault (KS-305). It stores ciphertext and nothing else."""

from __future__ import annotations

from sqlalchemy import ColumnElement, and_, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.ids import new_id
from keystone.db.models import Credential, Upstream
from keystone.db.session import affected
from keystone.identity.vault import (
    Cipher,
    CredentialInfo,
    Lookup,
    StoredCredential,
    UnknownUpstream,
    Vault,
)
from keystone.settings import Settings


class CredentialRepo:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def lookup(self, tenant_id: str, upstream_id: str, user_id: str | None) -> Lookup | None:
        """The upstream's credential mode with its static credential and, when `user_id` is
        given, that user's. None when the upstream does not exist."""
        owner: ColumnElement[bool] = Credential.user_id.is_(None)
        if user_id is not None:
            owner = or_(owner, Credential.user_id == user_id)
        statement = (
            select(
                Upstream.credential_mode,
                Credential.user_id,
                Credential.ciphertext,
                Credential.key_id,
            )
            .select_from(Upstream)
            .outerjoin(
                Credential,
                and_(
                    Credential.tenant_id == Upstream.tenant_id,
                    Credential.upstream_id == Upstream.id,
                    owner,
                ),
            )
            .where(Upstream.tenant_id == tenant_id, Upstream.id == upstream_id)
        )
        async with self._sessionmaker() as session:
            rows = (await session.execute(statement)).all()
        if not rows:
            return None
        static: StoredCredential | None = None
        per_user: StoredCredential | None = None
        for _mode, owner_id, ciphertext, kid in rows:
            if ciphertext is None:
                continue
            stored = StoredCredential(bytes(ciphertext), kid)
            if owner_id is None:
                static = stored
            else:
                per_user = stored
        return Lookup(mode=rows[0][0], static=static, per_user=per_user)

    async def put(
        self,
        tenant_id: str,
        upstream_id: str,
        user_id: str | None,
        ciphertext: bytes,
        key_id: str,
    ) -> None:
        insertion = insert(Credential).values(
            id=new_id(),
            tenant_id=tenant_id,
            upstream_id=upstream_id,
            user_id=user_id,
            ciphertext=ciphertext,
            key_id=key_id,
        )
        statement = insertion.on_conflict_do_update(
            constraint="uq_credentials_owner",
            set_={
                "ciphertext": insertion.excluded.ciphertext,
                "key_id": insertion.excluded.key_id,
                "rotated_at": func.now(),
            },
        )
        try:
            async with self._sessionmaker() as session, session.begin():
                await session.execute(statement)
        except IntegrityError as exc:
            if "fk_credentials_upstream" in str(exc):
                raise UnknownUpstream(f"there is no upstream {upstream_id!r}") from None
            raise

    async def infos(self) -> list[CredentialInfo]:
        statement = select(Credential).order_by(
            Credential.tenant_id, Credential.upstream_id, Credential.user_id.nulls_first()
        )
        async with self._sessionmaker() as session:
            return [
                CredentialInfo(
                    tenant_id=row.tenant_id,
                    upstream_id=row.upstream_id,
                    user_id=row.user_id,
                    key_id=row.key_id,
                    created_at=row.created_at,
                    rotated_at=row.rotated_at,
                )
                for row in (await session.scalars(statement)).all()
            ]

    async def rows(self) -> list[tuple[str, bytes, str]]:
        statement = select(Credential.id, Credential.ciphertext, Credential.key_id).order_by(
            Credential.id
        )
        async with self._sessionmaker() as session:
            found = await session.execute(statement)
            return [(row_id, bytes(data), kid) for row_id, data, kid in found]

    async def replace(self, row_id: str, old: bytes, new: bytes, key_id: str) -> bool:
        """Swap the ciphertext only if it is still `old`, so a rotation never undoes a `cred set`
        that ran in between."""
        statement = (
            update(Credential)
            .where(Credential.id == row_id, Credential.ciphertext == old)
            .values(ciphertext=new, key_id=key_id, rotated_at=func.now())
        )
        async with self._sessionmaker() as session, session.begin():
            return bool(affected(await session.execute(statement)))


def vault_from_settings(
    settings: Settings, sessionmaker: async_sessionmaker[AsyncSession]
) -> Vault | None:
    """The vault the master keys open, or None when no key is set. Raises VaultError for keys
    that cannot work, with a message that does not repeat them."""
    keys = settings.master_keys
    if keys is None or not keys.get_secret_value().strip():
        return None
    cipher = Cipher(keys, refuse_published=settings.env == "prod")
    return Vault(cipher, CredentialRepo(sessionmaker), cache_ttl_s=settings.credential_cache_ttl_s)
