import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC
from enum import StrEnum
from typing import Annotated, Any

import typer
import uvicorn
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from keystone import __version__
from keystone.app import create_app
from keystone.db.models import Upstream
from keystone.db.session import create_engine, make_sessionmaker
from keystone.gateway.upstreams import UpstreamDirectory, UpstreamPool, directory_client_factory
from keystone.logging import configure_logging
from keystone.registry.config import tool_overrides
from keystone.registry.naming import check_upstream_id
from keystone.registry.repo import Sessionmaker, ToolRepo, UpstreamRepo, UpstreamSpec
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
        notes[index] = [f"changed: {n}" for n in r.changed] + [f"removed: {n}" for n in r.removed]
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
