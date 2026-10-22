from datetime import UTC, datetime

import pytest
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.canonical import canonical_json, sha256_hex
from keystone.core.types import Principal, Risk, SessionState, ToolRef, ToolStatus, ToolTag
from keystone.db.models import McpSession, Tool
from keystone.db.tenants import upsert_tenants
from keystone.gateway.session_repo import SessionRepo
from keystone.registry.repo import ToolRepo, UpstreamRepo, UpstreamSpec, to_tool_ref
from keystone.settings import TenantConfig

pytestmark = [pytest.mark.phase(2), pytest.mark.services]

Maker = async_sessionmaker[AsyncSession]


async def seed(maker: Maker, *tenants: str) -> None:
    await upsert_tenants(maker, [TenantConfig(id=t, name=t.title()) for t in tenants or ("acme",)])


def spec(upstream_id: str = "mail", tenant: str = "acme", **fields: object) -> UpstreamSpec:
    return UpstreamSpec.model_validate(
        {"id": upstream_id, "tenant_id": tenant, "url": f"http://{upstream_id}:8101/mcp", **fields}
    )


def tool(
    name: str = "send_email", upstream: str = "mail", tenant: str = "acme", **fields: object
) -> ToolRef:
    description = f"{name} on {upstream}"
    schema = {"type": "object", "properties": {"to": {"type": "string"}}}
    values: dict[str, object] = {
        "name": f"{upstream}__{name}",
        "upstream_id": upstream,
        "upstream_tool_name": name,
        "tenant_id": tenant,
        "description": description,
        "input_schema": schema,
        "description_hash": sha256_hex(canonical_json(description)),
        "schema_hash": sha256_hex(canonical_json(schema)),
    }
    return ToolRef.model_validate(values | fields)


async def test_tool_roundtrip(sessionmaker: Maker) -> None:
    await seed(sessionmaker)
    await UpstreamRepo(sessionmaker).upsert(spec())
    original = tool(
        risk=Risk.HIGH,
        tags=frozenset({ToolTag.EXTERNAL_EFFECT, ToolTag.READS_SENSITIVE}),
        cost_per_call_usd=0.0023,
        timeout_s=12.5,
        extractors={"recipient_domain": "$.to | domain"},
        status=ToolStatus.ACTIVE,
    )
    repo = ToolRepo(sessionmaker)

    await repo.upsert(original)
    row = await repo.get("acme", original.name)

    assert row is not None
    assert to_tool_ref(row) == original
    assert row.last_seen_at is not None
    assert row.pending_description is None
    assert row.pending_schema is None


@pytest.mark.parametrize("cost", [0.0, 0.1, 0.30000000000000004, 1e-9, 12345.6789])
async def test_cost_survives_the_database_exactly(sessionmaker: Maker, cost: float) -> None:
    await seed(sessionmaker)
    await UpstreamRepo(sessionmaker).upsert(spec())
    repo = ToolRepo(sessionmaker)

    await repo.upsert(tool(cost_per_call_usd=cost))
    row = await repo.get("acme", "mail__send_email")

    assert row is not None
    assert to_tool_ref(row).cost_per_call_usd == cost


async def test_unique_tool_name_per_tenant(sessionmaker: Maker) -> None:
    await seed(sessionmaker, "acme", "globex")
    upstreams = UpstreamRepo(sessionmaker)
    await upstreams.upsert(spec("mail", "acme"))
    await upstreams.upsert(spec("gmail", "globex"))
    repo = ToolRepo(sessionmaker)

    await repo.upsert(tool("send_email", "mail", "acme", description="first"))
    await repo.upsert(tool("send_email", "mail", "acme", description="second"))
    # The same exposed name in another tenant is a different tool.
    await repo.upsert(
        tool("send_email", "gmail", "globex").model_copy(update={"name": "mail__send_email"})
    )

    acme = await repo.list_by_tenant("acme")
    globex = await repo.list_by_tenant("globex")
    assert [(t.name, t.description) for t in acme] == [("mail__send_email", "second")]
    assert [t.name for t in globex] == ["mail__send_email"]


async def test_the_database_refuses_a_duplicate_primary_key(sessionmaker: Maker) -> None:
    await seed(sessionmaker)
    await UpstreamRepo(sessionmaker).upsert(spec())
    await ToolRepo(sessionmaker).upsert(tool())
    duplicate = insert(Tool).values(
        tenant_id="acme",
        name="mail__send_email",
        upstream_id="mail",
        upstream_tool_name="send_email",
        description="d",
        input_schema={},
        description_hash="h",
        schema_hash="h",
    )

    with pytest.raises(IntegrityError):
        async with sessionmaker() as session, session.begin():
            await session.execute(duplicate)


async def test_a_tool_needs_an_upstream_of_the_same_tenant(sessionmaker: Maker) -> None:
    await seed(sessionmaker, "acme", "globex")
    await UpstreamRepo(sessionmaker).upsert(spec("mail", "acme"))

    with pytest.raises(IntegrityError):
        await ToolRepo(sessionmaker).upsert(tool("send_email", "mail", "globex"))
    with pytest.raises(IntegrityError):
        await ToolRepo(sessionmaker).upsert(tool("x", "nope", "acme"))


async def test_upstream_upsert_list_get_and_status(sessionmaker: Maker) -> None:
    await seed(sessionmaker, "acme", "globex")
    repo = UpstreamRepo(sessionmaker)

    await repo.upsert(spec("mail"))
    await repo.upsert(spec("files", transport="stdio", url=None, command=["python", "-m", "x"]))
    await repo.upsert(spec("gmail", "globex"))
    await repo.upsert(spec("mail", url="http://mail:9999/mcp"))  # an update, not a second row

    acme = await repo.list("acme")
    assert [u.id for u in acme] == ["files", "mail"]
    assert [u.id for u in await repo.list()] == ["files", "gmail", "mail"]
    mail = await repo.get("mail")
    assert mail is not None
    assert (mail.url, mail.status, mail.source, mail.credential_mode) == (
        "http://mail:9999/mcp",
        "unknown",
        "config",
        "none",
    )
    files = await repo.get("files")
    assert files is not None
    assert files.command == ["python", "-m", "x"]

    assert await repo.set_status("mail", "up") is True
    assert await repo.set_status("nope", "up") is False
    await repo.set_status("files", "disabled")
    assert [u.id for u in await repo.list("acme", include_disabled=False)] == ["mail"]
    # An update of the connection details leaves the status alone.
    await repo.upsert(spec("mail", url="http://mail:1/mcp"))
    refreshed = await repo.get("mail")
    assert refreshed is not None
    assert refreshed.status == "up"
    assert await repo.get("missing") is None


async def test_an_upstream_id_cannot_move_to_another_tenant(sessionmaker: Maker) -> None:
    await seed(sessionmaker, "acme", "globex")
    repo = UpstreamRepo(sessionmaker)
    await repo.upsert(spec("mail", "acme"))

    with pytest.raises(ValueError, match="another tenant"):
        await repo.upsert(spec("mail", "globex"))

    kept = await repo.get("mail")
    assert kept is not None
    assert kept.tenant_id == "acme"


async def test_record_sync_keeps_the_last_good_time_on_failure(sessionmaker: Maker) -> None:
    await seed(sessionmaker)
    repo = UpstreamRepo(sessionmaker)
    await repo.upsert(spec())

    await repo.record_sync("mail")
    good = await repo.get("mail")
    await repo.record_sync("mail", error="the upstream server is not reachable")
    failed = await repo.get("mail")
    await repo.record_sync("mail")
    recovered = await repo.get("mail")

    assert good is not None
    assert failed is not None
    assert recovered is not None
    assert good.last_sync_at is not None
    assert good.last_error is None
    assert failed.last_sync_at == good.last_sync_at
    assert failed.last_error == "the upstream server is not reachable"
    assert recovered.last_error is None


async def test_status_and_pending_changes(sessionmaker: Maker) -> None:
    await seed(sessionmaker)
    await UpstreamRepo(sessionmaker).upsert(spec())
    repo = ToolRepo(sessionmaker)
    original = tool()
    await repo.upsert(original)

    assert await repo.set_pending(
        "acme",
        original.name,
        description="new text",
        input_schema={"type": "object"},
        reason="description_changed",
    )
    held = await repo.get("acme", original.name)

    assert held is not None
    assert held.status == "quarantined"
    assert held.quarantine_reason == "description_changed"
    assert held.pending_description == "new text"
    assert held.pending_schema == {"type": "object"}
    # The live definition is untouched until someone approves the change.
    assert held.description == original.description
    assert held.description_hash == original.description_hash

    assert await repo.set_status("acme", original.name, ToolStatus.DISABLED, reason="gone")
    assert not await repo.set_status("acme", "mail__nope", ToolStatus.DISABLED)
    assert [t.name for t in await repo.list_by_tenant("acme", status=ToolStatus.DISABLED)] == [
        original.name
    ]
    assert await repo.list_by_tenant("acme", status=ToolStatus.ACTIVE) == []
    assert [t.name for t in await repo.list_by_upstream("acme", "mail")] == [original.name]


async def test_session_row_insert_and_touch(sessionmaker: Maker) -> None:
    await seed(sessionmaker)
    principal = Principal(tenant_id="acme", user_id="olivia", agent_id="ops-agent")
    started = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
    state = SessionState(session_id="s-1", principal=principal, created_at=started)
    repo = SessionRepo(sessionmaker)

    assert await repo.insert(state) is True
    assert await repo.insert(state) is False  # a second first call of the same session
    later = datetime(2026, 10, 21, 12, 5, tzinfo=UTC)
    assert await repo.touch(
        "s-1", later, flags=["reads_untrusted", "reads_untrusted"], tainted=True
    )
    assert not await repo.touch("s-missing", later)

    async with sessionmaker() as session:
        row = (await session.scalars(select(McpSession))).one()
    assert (row.id, row.tenant_id, row.user_id, row.agent_id) == (
        "s-1",
        "acme",
        "olivia",
        "ops-agent",
    )
    assert row.started_at == started
    assert row.last_seen_at == later
    assert row.final_flags == ["reads_untrusted"]
    assert row.tainted is True
