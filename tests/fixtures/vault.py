"""A credential store in memory, for tests of the vault that need no database."""

from datetime import UTC, datetime

from keystone.identity.vault import (
    CredentialInfo,
    Lookup,
    StoredCredential,
    UnknownUpstream,
)


class MemoryCredentialStore:
    """What `CredentialRepo` does, with a dict. `modes` maps an upstream id to its tenant and
    credential mode."""

    def __init__(self, modes: dict[str, tuple[str, str]]) -> None:
        self.modes = modes
        # (tenant, upstream, user) -> (row id, ciphertext, key_id, created, rotated)
        self.rows_by_owner: dict[
            tuple[str, str, str | None], tuple[str, bytes, str, datetime, datetime | None]
        ] = {}
        self._next = 0

    async def lookup(self, tenant_id: str, upstream_id: str, user_id: str | None) -> Lookup | None:
        known = self.modes.get(upstream_id)
        if known is None or known[0] != tenant_id:
            return None

        def stored(owner: str | None) -> StoredCredential | None:
            row = self.rows_by_owner.get((tenant_id, upstream_id, owner))
            return StoredCredential(row[1], row[2]) if row else None

        per_user = stored(user_id) if user_id is not None else None
        return Lookup(mode=known[1], static=stored(None), per_user=per_user)

    async def put(
        self,
        tenant_id: str,
        upstream_id: str,
        user_id: str | None,
        ciphertext: bytes,
        key_id: str,
    ) -> None:
        known = self.modes.get(upstream_id)
        if known is None or known[0] != tenant_id:
            raise UnknownUpstream(f"there is no upstream {upstream_id!r}")
        owner = (tenant_id, upstream_id, user_id)
        now = datetime.now(UTC)
        if owner in self.rows_by_owner:
            row_id, _, _, created, _ = self.rows_by_owner[owner]
            self.rows_by_owner[owner] = (row_id, ciphertext, key_id, created, now)
        else:
            self._next += 1
            self.rows_by_owner[owner] = (f"row-{self._next}", ciphertext, key_id, now, None)

    async def infos(self) -> list[CredentialInfo]:
        return [
            CredentialInfo(tenant, upstream, user, key_id, created, rotated)
            for (tenant, upstream, user), (_, _, key_id, created, rotated) in sorted(
                self.rows_by_owner.items(), key=lambda item: (*item[0][:2], item[0][2] or "")
            )
        ]

    async def rows(self) -> list[tuple[str, bytes, str]]:
        return [(row_id, data, kid) for row_id, data, kid, _, _ in self.rows_by_owner.values()]

    async def replace(self, row_id: str, old: bytes, new: bytes, key_id: str) -> bool:
        for owner, (stored_id, data, _, created, _) in self.rows_by_owner.items():
            if stored_id == row_id and data == old:
                self.rows_by_owner[owner] = (row_id, new, key_id, created, datetime.now(UTC))
                return True
        return False

    def ciphertexts(self) -> list[bytes]:
        return [row[1] for row in self.rows_by_owner.values()]
