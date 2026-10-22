import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC
from enum import StrEnum
from typing import Annotated, Any

import structlog
import typer
import uvicorn
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from keystone import __version__
from keystone.app import create_app
from keystone.core.types import ToolStatus
from keystone.db.models import Tool, Upstream
from keystone.db.session import create_engine, make_sessionmaker
from keystone.defense.description_check import check_description
from keystone.gateway.upstreams import UpstreamDirectory, UpstreamPool, directory_client_factory
from keystone.logging import configure_logging
from keystone.registry.config import tool_overrides
from keystone.registry.naming import check_upstream_id
from keystone.registry.pinning import (
    OPERATOR_DISABLED,
    REMOVED,
    pending_fingerprint,
    schema_text,
    unified_diff,
)
from keystone.registry.repo import (
    PinningError,
    Sessionmaker,
    ToolRepo,
    UpstreamRepo,
    UpstreamSpec,
)
from keystone.registry.ssrf import UnsafeUpstreamUrl, check_upstream_url
from keystone.registry.sync import RegistrySyncer, SyncReport
from keystone.settings import Settings

app = typer.Typer(help="Keystone admin CLI.", no_args_is_help=True, add_completion=False)
upstream_app = typer.Typer(
    help="Register and inspect upstream MCP servers.", no_args_is_help=True, add_completion=False
)
app.add_typer(upstream_app, name="upstream")
registry_app = typer.Typer(
    help="Inspect and sync the tool registry.", no_args_is_help=True, add_completion=False
)
app.add_typer(registry_app, name="registry")
tool_app = typer.Typer(
    help="Review, approve and disable tools.", no_args_is_help=True, add_completion=False
)
app.add_typer(tool_app, name="tool")
log = structlog.get_logger()


class CliError(Exception):
    """A problem the operator can fix. The message is printed as it is, without a traceback."""


def run_with_database[T](action: Callable[[Settings, Sessionmaker], Awaitable[T]]) -> T:
    """Run one admin action against the configured database, then close the connection pool.
    A CliError ends the command with exit code 1."""
    settings = Settings()

    async def main() -> T:
        engine = create_engine(settings.database_url.get_secret_value())
        try:
            return await action(settings, make_sessionmaker(engine))
        finally:
            await engine.dispose()

    try:
        return asyncio.run(main())
    except CliError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    except (OSError, SQLAlchemyError) as exc:
        # The text of these errors can hold the connection string, so print the type only.
        typer.echo(f"error: cannot use the database ({type(exc).__name__})", err=True)
        raise typer.Exit(1) from None


def migrate_database(url: str) -> None:
    """Bring the schema to the latest revision. Alembic runs its own event loop, so call this
    before any other loop starts."""
    config = Config()
    config.set_main_option("script_location", "keystone.db:migrations")
    config.attributes["url"] = url
    config.attributes["configure_logging"] = False
    command.upgrade(config, "head")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Address to bind."),
    port: int = typer.Option(8080, help="Port to listen on."),
    migrate: bool = typer.Option(False, "--migrate", help="Apply database migrations first."),
) -> None:
    """Run the gateway."""
    settings = Settings()
    configure_logging(settings.log_level)
    if migrate:
        migrate_database(settings.database_url.get_secret_value())
    uvicorn.run(create_app(settings), host=host, port=port)


db_app = typer.Typer(help="Database schema.", no_args_is_help=True, add_completion=False)
app.add_typer(db_app, name="db")


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Apply database migrations. Running it twice changes nothing."""
    try:
        migrate_database(Settings().database_url.get_secret_value())
    except (OSError, SQLAlchemyError) as exc:
        typer.echo(f"error: cannot use the database ({type(exc).__name__})", err=True)
        raise typer.Exit(1) from None
    typer.echo("database is up to date")


@app.command()
def version() -> None:
    """Print the package version."""
    typer.echo(f"keystone {__version__}")


class TransportChoice(StrEnum):
    HTTP = "http"
    STDIO = "stdio"


def _when(row: Upstream) -> str:
    stamp = row.last_sync_at
    return "never" if stamp is None else stamp.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def _target(row: Upstream) -> str:
    return row.url or " ".join(row.command or []) or "-"


def _as_dict(row: Upstream) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant": row.tenant_id,
        "transport": row.transport,
        "status": row.status,
        "source": row.source,
        "target": _target(row),
        "last_sync_at": row.last_sync_at.isoformat() if row.last_sync_at else None,
        "last_error": row.last_error,
    }


def render_upstreams(rows: list[Upstream]) -> str:
    header = ("ID", "TENANT", "TRANSPORT", "STATUS", "SOURCE", "LAST SYNC", "TARGET")
    table = [header] + [
        (r.id, r.tenant_id, r.transport, r.status, r.source, _when(r), _target(r)) for r in rows
    ]
    widths = [max(len(line[i]) for line in table) for i in range(len(header))]
    lines: list[str] = []
    for index, line in enumerate(table):
        lines.append(
            "  ".join(cell.ljust(w) for cell, w in zip(line, widths, strict=True)).rstrip()
        )
        if index > 0 and rows[index - 1].last_error:
            lines.append(f"  last error: {rows[index - 1].last_error}")
    return "\n".join(lines)


@upstream_app.command("list")
def upstream_list(
    tenant: Annotated[str | None, typer.Option(help="Only this tenant.")] = None,
    all_: Annotated[bool, typer.Option("--all", help="Include disabled upstreams.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
) -> None:
    """List upstreams with their status."""

    async def action(settings: Settings, sessions: Sessionmaker) -> list[Upstream]:
        return list(await UpstreamRepo(sessions).list(tenant, include_disabled=all_))

    rows = run_with_database(action)
    if as_json:
        typer.echo(json.dumps([_as_dict(r) for r in rows], indent=2))
    elif rows:
        typer.echo(render_upstreams(rows))
    else:
        typer.echo("no upstreams registered")


@upstream_app.command("add")
def upstream_add(
    upstream_id: Annotated[str, typer.Argument(metavar="ID", help="Lowercase id, e.g. crm.")],
    command: Annotated[
        list[str] | None,
        typer.Argument(metavar="[COMMAND]...", help="For stdio: the program and its arguments."),
    ] = None,
    url: Annotated[str | None, typer.Option(help="The MCP endpoint, for http.")] = None,
    tenant: Annotated[str | None, typer.Option(help="Tenant id. Default: the only tenant.")] = None,
    transport: Annotated[TransportChoice, typer.Option(help="How to reach it.")] = (
        TransportChoice.HTTP
    ),
) -> None:
    """Register an upstream (source: cli). It is synced with the next registry sync."""

    async def action(settings: Settings, sessions: Sessionmaker) -> str:
        try:
            check_upstream_id(upstream_id)
        except ValueError as exc:
            raise CliError(str(exc)) from exc
        tenant_id = tenant or _only_tenant(settings)
        if transport is TransportChoice.HTTP:
            if not url:
                raise CliError("an http upstream needs --url")
            try:
                await asyncio.to_thread(check_upstream_url, url, settings.allow_private_upstreams)
            except UnsafeUpstreamUrl as exc:
                raise CliError(f"url refused: {exc}") from exc
        elif not command:
            raise CliError("a stdio upstream needs a command after the id")
        repo = UpstreamRepo(sessions)
        existing = await repo.get(upstream_id)
        if existing is not None and existing.source == "config":
            raise CliError(f"upstream {upstream_id!r} comes from the config file; edit it there")
        spec = UpstreamSpec(
            id=upstream_id,
            tenant_id=tenant_id,
            transport="http" if transport is TransportChoice.HTTP else "stdio",
            url=url if transport is TransportChoice.HTTP else None,
            command=list(command) if transport is TransportChoice.STDIO and command else None,
            source="cli",
        )
        try:
            await repo.upsert(spec)
        except ValueError as exc:
            raise CliError(str(exc)) from exc
        except IntegrityError as exc:
            if "upstreams_tenant_id_fkey" in str(exc):
                raise CliError(f"there is no tenant {tenant_id!r}") from exc
            raise
        if existing is not None and existing.status == "disabled":
            await repo.set_status(upstream_id, "unknown")
        return "updated" if existing is not None else "added"

    typer.echo(f"{run_with_database(action)} upstream {upstream_id}")


@upstream_app.command("remove")
def upstream_remove(
    upstream_id: Annotated[str, typer.Argument(metavar="ID")],
) -> None:
    """Disable an upstream added by the CLI. Its history stays; nothing is deleted."""

    async def action(settings: Settings, sessions: Sessionmaker) -> str:
        repo = UpstreamRepo(sessions)
        row = await repo.get(upstream_id)
        if row is None:
            raise CliError(f"there is no upstream {upstream_id!r}")
        if row.source == "config":
            raise CliError(
                f"upstream {upstream_id!r} comes from the config file; "
                "remove it there and restart Keystone"
            )
        if row.status == "disabled":
            return "already disabled"
        await repo.set_status(upstream_id, "disabled")
        return "disabled"

    typer.echo(f"upstream {upstream_id} {run_with_database(action)}")


def _only_tenant(settings: Settings) -> str:
    if len(settings.tenants) == 1:
        return settings.tenants[0].id
    raise CliError("pass --tenant: the config does not name exactly one tenant")


async def run_sync(
    settings: Settings, sessions: Sessionmaker, upstream_id: str | None
) -> list[SyncReport]:
    """Sync from this process with a pool of its own. A running gateway sees the result within its
    registry cache time (registry.cache_ttl_s)."""
    directory = UpstreamDirectory()
    async with UpstreamPool(directory_client_factory(directory)) as pool:
        syncer = RegistrySyncer(
            UpstreamRepo(sessions),
            ToolRepo(sessions),
            pool,
            directory,
            overrides=tool_overrides(settings.upstreams),
            timeout_s=settings.registry.sync_timeout_s,
        )
        if upstream_id is not None:
            return [await syncer.sync_upstream(upstream_id)]
        return await syncer.sync_all()


def render_reports(reports: list[SyncReport]) -> str:
    header = ("UPSTREAM", "CREATED", "UNCHANGED", "CHANGED", "REMOVED", "RESULT")
    table = [header]
    notes: dict[int, list[str]] = {}
    for index, r in enumerate(reports, start=1):
        counts = (
            str(len(r.created)),
            str(len(r.unchanged)),
            str(len(r.changed)),
            str(len(r.removed)),
        )
        table.append((r.upstream_id, *counts, "ok" if r.ok else "failed"))
        held = set(r.quarantined)
        notes[index] = [
            f"changed: {n}" + (" (quarantined)" if n in held else "") for n in r.changed
        ]
        notes[index] += [f"removed: {n}" for n in r.removed]
        notes[index] += [f"error: {e}" for e in r.errors]
    widths = [max(len(line[i]) for line in table) for i in range(len(header))]
    lines: list[str] = []
    for index, line in enumerate(table):
        lines.append(
            "  ".join(cell.ljust(w) for cell, w in zip(line, widths, strict=True)).rstrip()
        )
        lines += [f"  {note}" for note in notes.get(index, [])]
    return "\n".join(lines)


def sync_command(upstream_id: str | None, as_json: bool) -> None:
    reports = run_with_database(
        lambda settings, sessions: run_sync(settings, sessions, upstream_id)
    )
    if as_json:
        typer.echo(json.dumps([r.model_dump() for r in reports], indent=2))
    elif reports:
        typer.echo(render_reports(reports))
    else:
        typer.echo("no upstreams to sync")
    if any(not r.ok for r in reports):
        raise typer.Exit(1)


@registry_app.command("sync")
def registry_sync(
    upstream: Annotated[
        str | None, typer.Option("--upstream", help="Only this upstream. Default: all.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
) -> None:
    """Read every upstream's tools now. Exits 1 if any upstream could not be synced."""
    sync_command(upstream, as_json)


@upstream_app.command("sync")
def upstream_sync(
    upstream_id: Annotated[str, typer.Argument(metavar="ID")],
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
) -> None:
    """Read one upstream's tools now (the same as `registry sync --upstream ID`)."""
    sync_command(upstream_id, as_json)


async def find_tool(
    settings: Settings, sessions: Sessionmaker, name: str, tenant: str | None
) -> Tool:
    """The tool called `name`. The tenant is `--tenant`, else the config's only tenant, else the
    only tenant that has a tool of that name."""
    repo = ToolRepo(sessions)
    if tenant is None and len(settings.tenants) == 1:
        tenant = settings.tenants[0].id
    if tenant is not None:
        found = await repo.get(tenant, name)
        if found is None:
            raise CliError(f"there is no tool {name!r} in tenant {tenant!r}")
        return found
    async with sessions() as session:
        rows = (await session.scalars(select(Tool).where(Tool.name == name))).all()
    if not rows:
        raise CliError(f"there is no tool {name!r}")
    if len(rows) > 1:
        raise CliError(f"tool {name!r} exists in several tenants: pass --tenant")
    return rows[0]


def render_tool(tool: Tool) -> str:
    lines = [
        f"{tool.name}  (upstream {tool.upstream_id}, tenant {tool.tenant_id})",
        f"status:   {tool.status}"
        + (f" ({tool.quarantine_reason})" if tool.quarantine_reason else ""),
        f"risk:     {tool.risk}   tags: {', '.join(tool.tags) or '-'}",
        "pinned:   description sha256 "
        f"{tool.description_hash[:12]}, schema sha256 {tool.schema_hash[:12]}",
    ]
    if tool.pending_description is not None and tool.pending_schema is not None:
        fingerprint = pending_fingerprint(tool.pending_description, tool.pending_schema)
        lines.append(f"pending:  fingerprint {fingerprint[:12]}")
        command = f"keystone tool approve-change {tool.name} --expect {fingerprint[:12]}"
        lines.append(f"          to accept it: {command}")
    lines += ["", "description (current):", indent(tool.description)]
    if hits := check_description(tool.description):
        lines.append(f"  screening: {', '.join(hits)}")
    if tool.pending_description is not None and tool.pending_schema is not None:
        lines += ["", "description (pending):", indent(tool.pending_description)]
        if hits := check_description(tool.pending_description):
            lines.append(f"  screening: {', '.join(hits)}")
        description_diff = unified_diff(tool.description, tool.pending_description, "description")
        schema_diff = unified_diff(
            schema_text(tool.input_schema), schema_text(tool.pending_schema), "schema"
        )
        lines += ["", "diff:", indent(description_diff or "(the description is the same)")]
        if schema_diff:
            lines += ["", indent(schema_diff)]
        else:
            lines += ["", indent("(the schema is the same)")]
    return "\n".join(lines)


def indent(text: str) -> str:
    return "\n".join(f"  {line}" for line in text.splitlines() or [""])


@tool_app.command("list")
def tool_list(
    status: Annotated[
        str | None,
        typer.Option(help="Only tools with this status (active, quarantined, disabled)."),
    ] = None,
    tenant: Annotated[str | None, typer.Option(help="Tenant id. Default: the only tenant.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
) -> None:
    """List tools with their status."""

    async def action(settings: Settings, sessions: Sessionmaker) -> list[Tool]:
        tenant_id = tenant or (settings.tenants[0].id if len(settings.tenants) == 1 else None)
        wanted = None
        if status is not None:
            try:
                wanted = ToolStatus(status)
            except ValueError:
                raise CliError("status must be active, quarantined or disabled") from None
        statement = select(Tool).order_by(Tool.tenant_id, Tool.name)
        if tenant_id is not None:
            statement = statement.where(Tool.tenant_id == tenant_id)
        if wanted is not None:
            statement = statement.where(Tool.status == wanted.value)
        async with sessions() as session:
            return list((await session.scalars(statement)).all())

    rows = run_with_database(action)
    if as_json:
        typer.echo(
            json.dumps(
                [
                    {
                        "name": t.name,
                        "tenant": t.tenant_id,
                        "status": t.status,
                        "reason": t.quarantine_reason,
                        "risk": t.risk,
                    }
                    for t in rows
                ],
                indent=2,
            )
        )
        return
    if not rows:
        typer.echo("no tools")
        return
    table = [("NAME", "TENANT", "STATUS", "RISK", "REASON")] + [
        (t.name, t.tenant_id, t.status, t.risk, t.quarantine_reason or "-") for t in rows
    ]
    widths = [max(len(line[i]) for line in table) for i in range(5)]
    for line in table:
        typer.echo("  ".join(cell.ljust(w) for cell, w in zip(line, widths, strict=True)).rstrip())


@tool_app.command("show")
def tool_show(
    name: Annotated[str, typer.Argument(metavar="NAME", help="Exposed name, e.g. echo__echo.")],
    tenant: Annotated[str | None, typer.Option(help="Tenant id.")] = None,
) -> None:
    """Print a tool's current definition and, if it is held, the pending one with a diff."""

    async def action(settings: Settings, sessions: Sessionmaker) -> str:
        return render_tool(await find_tool(settings, sessions, name, tenant))

    typer.echo(run_with_database(action))


@tool_app.command("approve-change")
def tool_approve_change(
    name: Annotated[str, typer.Argument(metavar="NAME")],
    note: Annotated[str | None, typer.Option(help="Why you accept it. Goes in the log.")] = None,
    expect: Annotated[
        str | None,
        typer.Option(help="The fingerprint `tool show` printed. Refuses if the pending changed."),
    ] = None,
    tenant: Annotated[str | None, typer.Option(help="Tenant id.")] = None,
) -> None:
    """Accept the pending definition of a quarantined tool and make the tool active again."""

    async def action(settings: Settings, sessions: Sessionmaker) -> str:
        found = await find_tool(settings, sessions, name, tenant)
        try:
            row = await ToolRepo(sessions).approve_change(found.tenant_id, name, expect_hash=expect)
        except PinningError as exc:
            raise CliError(str(exc)) from exc
        log.warning(
            "tool_change_approved",
            tool=name,
            tenant=found.tenant_id,
            was=found.quarantine_reason,
            description_hash=row.description_hash,
            note=note,
        )
        return f"approved {name}: active with description sha256 {row.description_hash[:12]}"

    typer.echo(run_with_database(action))


@tool_app.command("disable")
def tool_disable(
    name: Annotated[str, typer.Argument(metavar="NAME")],
    tenant: Annotated[str | None, typer.Option(help="Tenant id.")] = None,
) -> None:
    """Take a tool out of the list and refuse calls to it. Sync will not turn it back on."""

    async def action(settings: Settings, sessions: Sessionmaker) -> str:
        found = await find_tool(settings, sessions, name, tenant)
        await ToolRepo(sessions).set_status(
            found.tenant_id, name, ToolStatus.DISABLED, reason=OPERATOR_DISABLED
        )
        return f"disabled {name}"

    typer.echo(run_with_database(action))


@tool_app.command("enable")
def tool_enable(
    name: Annotated[str, typer.Argument(metavar="NAME")],
    tenant: Annotated[str | None, typer.Option(help="Tenant id.")] = None,
) -> None:
    """Turn a tool you disabled back on."""

    async def action(settings: Settings, sessions: Sessionmaker) -> str:
        found = await find_tool(settings, sessions, name, tenant)
        if found.status == ToolStatus.ACTIVE.value:
            return f"{name} is already active"
        if found.status == ToolStatus.QUARANTINED.value:
            raise CliError(f"{name} is quarantined: review it, then use approve-change")
        if found.quarantine_reason != OPERATOR_DISABLED:
            why = (
                "its upstream no longer lists it"
                if found.quarantine_reason == REMOVED
                else "it was not disabled by an operator"
            )
            raise CliError(f"{name} cannot be enabled by hand: {why}")
        await ToolRepo(sessions).set_status(found.tenant_id, name, ToolStatus.ACTIVE)
        return f"enabled {name}"

    typer.echo(run_with_database(action))
