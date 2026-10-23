"""The `policy_versions` table (KS-403): every policy set that was loaded."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.db.models import PolicyVersion
from keystone.policy.store import PolicySet


class PolicyVersionRepo:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def record(self, policy_set: PolicySet) -> None:
        """Keep the files of this version. A version that is already there stays as it was: the
        same files, and the time it was first loaded."""
        statement = (
            insert(PolicyVersion)
            .values(
                version=policy_set.version,
                files=[
                    {"path": f.path, "sha256": f.sha256, "content": f.content}
                    for f in policy_set.files
                ],
            )
            .on_conflict_do_nothing(index_elements=[PolicyVersion.version])
        )
        async with self._sessionmaker() as session, session.begin():
            await session.execute(statement)

    async def versions(self) -> list[str]:
        """Every recorded version, oldest first."""
        async with self._sessionmaker() as session:
            rows = await session.execute(
                select(PolicyVersion.version).order_by(
                    PolicyVersion.loaded_at, PolicyVersion.version
                )
            )
            return list(rows.scalars())
