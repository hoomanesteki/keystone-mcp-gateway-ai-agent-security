from collections.abc import Sequence

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.db.models import Tenant
from keystone.settings import TenantConfig


async def upsert_tenants(
    sessionmaker: async_sessionmaker[AsyncSession], tenants: Sequence[TenantConfig]
) -> None:
    if not tenants:
        return
    statement = insert(Tenant).values([{"id": t.id, "name": t.name} for t in tenants])
    statement = statement.on_conflict_do_update(
        index_elements=[Tenant.id], set_={"name": statement.excluded.name}
    )
    async with sessionmaker() as session, session.begin():
        await session.execute(statement)
