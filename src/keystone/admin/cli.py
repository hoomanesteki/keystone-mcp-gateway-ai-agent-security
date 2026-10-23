import asyncio
import json
import os
import sys
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import httpx2
import structlog
import typer
import uvicorn
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from keystone import __version__
from keystone.admin.tools import ToolAdmin, ToolConflict, ToolNotFound
from keystone.app import create_app
from keystone.audit.verify import Verdict, export_records, verify_chain
from keystone.core.types import ToolStatus
from keystone.db.models import Tool, Upstream
from keystone.db.session import create_engine, make_sessionmaker
from keystone.defense.description_check import check_description
from keystone.gateway.upstreams import UpstreamDirectory, UpstreamPool, directory_client_factory
from keystone.identity.credential_repo import CredentialRepo, vault_from_settings
from keystone.identity.middleware import AuthConfigError
from keystone.identity.vault import UnknownUpstream, Vault, VaultError
from keystone.logging import configure_logging
from keystone.policy.store import PolicyLoadError
from keystone.policy.testrunner import CaseError
from keystone.policy.testrunner import render as render_report
from keystone.policy.testrunner import run as run_policy_cases
from keystone.registry.config import stdio_environments, tool_overrides
from keystone.registry.naming import check_upstream_id
from keystone.registry.pinning import (
    pending_fingerprint,
    schema_text,
    unified_diff,
)
from keystone.registry.repo import (
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
agent_app = typer.Typer(help="Agents that may connect.", no_args_is_help=True, add_completion=False)
app.add_typer(agent_app, name="agent")
cred_app = typer.Typer(
    help="Upstream credentials in the vault.", no_args_is_help=True, add_completion=False
)
app.add_typer(cred_app, name="cred")
policy_app = typer.Typer(
    help="Policies as code: reload them into a running Keystone.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(policy_app, name="policy")
audit_app = typer.Typer(
    help="The audit log: check its hash chain and export it.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(audit_app, name="audit")
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


def migration_url(settings: Settings) -> str:
    """Where migrations connect: the owner of the tables when one is configured."""
    return (settings.migrate_database_url or settings.database_url).get_secret_value()


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
    try:
        settings = Settings()
    except ValueError as exc:
        typer.echo(f"error: invalid settings: {exc}", err=True)
        raise typer.Exit(1) from None
    configure_logging(settings.log_level)
    try:
        # Built before the migration, so a configuration that cannot work stops here.
        gateway_app = create_app(settings)
    except (AuthConfigError, VaultError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    except PolicyLoadError as exc:
        typer.echo("error: the policies cannot be loaded:", err=True)
        for problem in exc.problems:
            typer.echo(f"  {problem}", err=True)
        raise typer.Exit(1) from None
    if migrate:
        migrate_database(migration_url(settings))
    uvicorn.run(gateway_app, host=host, port=port)


db_app = typer.Typer(help="Database schema.", no_args_is_help=True, add_completion=False)
app.add_typer(db_app, name="db")


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Apply database migrations. Running it twice changes nothing."""
    try:
        migrate_database(migration_url(Settings()))
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
    try:
        vault = vault_from_settings(settings, sessions)
    except VaultError as exc:
        raise CliError(str(exc)) from exc
    async with UpstreamPool(directory_client_factory(directory)) as pool:
        syncer = RegistrySyncer(
            UpstreamRepo(sessions),
            ToolRepo(sessions),
            pool,
            directory,
            overrides=tool_overrides(settings.upstreams),
            timeout_s=settings.registry.sync_timeout_s,
            environments=stdio_environments(settings.upstreams),
            service_headers=vault.service_headers if vault else None,
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
            row = await ToolAdmin(sessions).approve_change(
                found.tenant_id, name, expect=expect, note=note
            )
        except (ToolConflict, ToolNotFound) as exc:
            raise CliError(str(exc)) from exc
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
        try:
            await ToolAdmin(sessions).disable(found.tenant_id, name)
        except (ToolConflict, ToolNotFound) as exc:
            raise CliError(str(exc)) from exc
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
        try:
            _, changed = await ToolAdmin(sessions).enable(found.tenant_id, name)
        except (ToolConflict, ToolNotFound) as exc:
            raise CliError(str(exc)) from exc
        return f"enabled {name}" if changed else f"{name} is already active"

    typer.echo(run_with_database(action))


def unknown_agent_policy(settings: Settings) -> str:
    return "allowed with trust low" if settings.auth.allow_unknown_agents else "refused (403)"


@agent_app.command("list")
def agent_list(
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
) -> None:
    """List the agents in the config with their trust level, and say what an unlisted one gets."""
    settings = Settings()
    agents = sorted(settings.agents.items())
    policy = unknown_agent_policy(settings)
    if as_json:
        listed = [{"id": agent_id, "trust": agent.trust} for agent_id, agent in agents]
        typer.echo(json.dumps({"agents": listed, "unknown_agents": policy}, indent=2))
        return
    if agents:
        table = [("AGENT", "TRUST"), *((agent_id, agent.trust) for agent_id, agent in agents)]
        width = max(len(row[0]) for row in table)
        for agent_id, trust in table:
            typer.echo(f"{agent_id.ljust(width)}  {trust}".rstrip())
    else:
        typer.echo("no agents configured")
    typer.echo(f"\nunknown agents: {policy}")


def open_vault(settings: Settings, sessions: Sessionmaker) -> Vault:
    try:
        vault = vault_from_settings(settings, sessions)
    except VaultError as exc:
        raise CliError(str(exc)) from exc
    if vault is None:
        raise CliError("KEYSTONE_MASTER_KEYS is not set")
    return vault


def read_secret(from_env: str | None) -> str:
    """The credential value, from an environment variable, a hidden prompt on a terminal, or
    standard input. Never from the command line, where a process list would show it."""
    if from_env:
        value = os.environ.get(from_env, "")
        if not value:
            raise CliError(f"{from_env} is not set")
    elif sys.stdin.isatty():
        value = typer.prompt("Value", hide_input=True)
    else:
        value = sys.stdin.read()
    value = value.rstrip("\r\n")
    if not value:
        raise CliError("the value is empty")
    return value


@cred_app.command("set")
def cred_set(
    upstream: Annotated[str, typer.Option("--upstream", help="Upstream id, for example mail.")],
    header: Annotated[str, typer.Option("--header", help="Header to send, for example X-Api-Key.")],
    user: Annotated[
        str | None,
        typer.Option("--user", help="Only for this user (per_user upstreams). Default: for all."),
    ] = None,
    from_env: Annotated[
        str | None,
        typer.Option("--from-env", help="Read the value from this variable, not standard input."),
    ] = None,
) -> None:
    """Store the credential of an upstream, replacing the one there. The value is read from
    standard input (or --from-env), never from an argument."""
    try:
        value = read_secret(from_env)
    except CliError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None

    async def action(settings: Settings, sessions: Sessionmaker) -> str:
        row = await UpstreamRepo(sessions).get(upstream)
        if row is None:
            raise CliError(f"there is no upstream {upstream!r}")
        vault = open_vault(settings, sessions)
        try:
            await vault.set(row.tenant_id, upstream, {header: value}, user)
        except (ValueError, UnknownUpstream) as exc:
            raise CliError(str(exc)) from exc
        if row.credential_mode == "none":
            typer.echo(f"warning: {upstream} has credential_mode none; it is never sent", err=True)
        elif user and row.credential_mode == "static":
            typer.echo(f"warning: {upstream} is static; a per-user credential is unused", err=True)
        owner = f"user {user}" if user else "all callers"
        return f"stored the credential of {upstream} for {owner}"

    typer.echo(run_with_database(action))


@cred_app.command("list")
def cred_list(
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
) -> None:
    """List stored credentials: whom they are for and when they were written. Nothing that could
    reveal a value."""

    def stamp(moment: datetime | None) -> str | None:
        return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%SZ") if moment else None

    async def action(settings: Settings, sessions: Sessionmaker) -> list[dict[str, Any]]:
        return [
            {
                "tenant": info.tenant_id,
                "upstream": info.upstream_id,
                "user": info.user_id,
                "key_id": info.key_id,
                "created_at": stamp(info.created_at),
                "rotated_at": stamp(info.rotated_at),
            }
            for info in await CredentialRepo(sessions).infos()
        ]

    rows = run_with_database(action)
    if as_json:
        typer.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        typer.echo("no credentials stored")
        return
    table = [("TENANT", "UPSTREAM", "USER", "KEY ID", "CREATED", "ROTATED")] + [
        (
            r["tenant"],
            r["upstream"],
            r["user"] or "-",
            r["key_id"],
            r["created_at"],
            r["rotated_at"] or "-",
        )
        for r in rows
    ]
    widths = [max(len(line[i]) for line in table) for i in range(6)]
    for line in table:
        typer.echo("  ".join(cell.ljust(w) for cell, w in zip(line, widths, strict=True)).rstrip())


@cred_app.command("rotate-keys")
def cred_rotate_keys() -> None:
    """Re-encrypt every credential under the first key of KEYSTONE_MASTER_KEYS. Put the new key
    first and keep the old one until this has run; then remove the old one."""

    async def action(settings: Settings, sessions: Sessionmaker) -> tuple[str, bool]:
        report = await open_vault(settings, sessions).rotate_keys()
        text = f"rotated {report.rotated}, already under the first key {report.unchanged}"
        if report.failed:
            text += f", could not decrypt {len(report.failed)}: {', '.join(report.failed)}"
        return text, not report.failed

    text, ok = run_with_database(action)
    typer.echo(text)
    if not ok:
        raise typer.Exit(1)


RELOAD_PATH = "/admin/api/v1/policies/reload"
RELOAD_TIMEOUT_S = 30.0


@policy_app.command("reload")
def policy_reload(
    url: Annotated[
        str,
        typer.Option(
            "--url", envvar="KEYSTONE_ADMIN_URL", help="Base address of the running Keystone."
        ),
    ] = "http://localhost:8080",
    token: Annotated[
        str | None,
        typer.Option(
            "--token",
            envvar="KEYSTONE_ADMIN_TOKEN",
            help="Access token of a user with the admin role. Prefer the environment variable: "
            "an argument shows in the process list.",
        ),
    ] = None,
) -> None:
    """Make a running Keystone read its policy files again. A set with any problem is refused,
    every problem is printed, and the set in force stays in force (exit code 1)."""
    if not token:
        typer.echo("error: no token: use --token or set KEYSTONE_ADMIN_TOKEN", err=True)
        raise typer.Exit(1)
    endpoint = url.rstrip("/") + RELOAD_PATH
    try:
        response = httpx2.post(
            endpoint, headers={"Authorization": f"Bearer {token}"}, timeout=RELOAD_TIMEOUT_S
        )
    except httpx2.HTTPError as exc:
        # The text of these errors can hold the address with credentials in it, so print the type.
        typer.echo(f"error: cannot reach Keystone at {url} ({type(exc).__name__})", err=True)
        raise typer.Exit(1) from None
    try:
        body = response.json()
    except ValueError:
        body = {}
    if response.status_code == 200:
        state = "changed" if body.get("changed") else "unchanged"
        typer.echo(f"policies reloaded: version {str(body.get('version'))[:12]} ({state})")
        return
    if response.status_code == 422:
        typer.echo(
            f"error: the new policies were refused; version {str(body.get('version'))[:12]} "
            "stays in force:",
            err=True,
        )
        for problem in body.get("errors", []):
            typer.echo(f"  {problem}", err=True)
        raise typer.Exit(1)
    why = body.get("reason") or body.get("error") or "no reason given"
    typer.echo(f"error: Keystone answered {response.status_code} ({why})", err=True)
    raise typer.Exit(1)


@policy_app.command("test")
def policy_test(
    policy_root: Annotated[
        Path, typer.Argument(metavar="POLICY_ROOT", help="The directory with the policies.")
    ],
    cases: Annotated[
        list[Path],
        typer.Argument(metavar="CASES...", help="Case files, or directories that hold them."),
    ],
    coverage: Annotated[
        bool,
        typer.Option(
            "--coverage",
            help="Also list the policies no case matched, and fail if there are any.",
        ),
    ] = False,
) -> None:
    """Check that the policies decide the cases as the cases say (see docs/policies.md). Prints a
    table, and exits 1 if any case fails, the policies or the cases cannot be read, or, with
    --coverage, a policy was matched by no case."""
    try:
        report = run_policy_cases(policy_root, cases, coverage=coverage)
    except PolicyLoadError as exc:
        typer.echo("error: the policies cannot be loaded:", err=True)
        for problem in exc.problems:
            typer.echo(f"  {problem}", err=True)
        raise typer.Exit(1) from None
    except CaseError as exc:
        typer.echo("error: the cases cannot be read:", err=True)
        for problem in exc.problems:
            typer.echo(f"  {problem}", err=True)
        raise typer.Exit(1) from None
    typer.echo(render_report(report))
    if not report.ok:
        raise typer.Exit(1)


@audit_app.command("verify")
def audit_verify(
    from_seq: Annotated[
        int | None,
        typer.Option(
            "--from-seq",
            min=1,
            help="Start at this seq. The record before it anchors the check and is not itself "
            "checked, so records before it are not.",
        ),
    ] = None,
) -> None:
    """Recompute the hash chain from the rows in Postgres. Prints `OK, N records`, or
    `broken at seq K: hash mismatch` or `broken at seq K: gap` and exits with code 2."""

    async def action(settings: Settings, sessions: Sessionmaker) -> Verdict:
        return await verify_chain(sessions, from_seq=from_seq)

    verdict = run_with_database(action)
    typer.echo(verdict.message)
    if not verdict.ok:
        raise typer.Exit(2)


def parse_moment(option: str, text: str) -> datetime:
    """A date or a date and time. Without a zone it is UTC."""
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise CliError(
            f"{option}: cannot read {text!r}; write a date or a time such as 2026-10-01 or "
            "2026-10-01T12:00:00Z"
        ) from None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


@audit_app.command("export")
def audit_export(
    since: Annotated[
        str | None, typer.Option("--since", help="From this date or time on (UTC unless it says).")
    ] = None,
    until: Annotated[
        str | None, typer.Option("--until", help="Up to, and not including, this date or time.")
    ] = None,
    tenant: Annotated[str | None, typer.Option("--tenant", help="Only this tenant.")] = None,
) -> None:
    """Write the records as JSON lines to standard output, in seq order. Each line holds the
    columns of one record in the form its hash covers, so it can be checked on its own: the hash is
    the sha256 of the previous hash (as bytes) and the canonical JSON of the line without `seq`,
    `prev_hash` and `hash`."""

    async def action(settings: Settings, sessions: Sessionmaker) -> None:
        start = parse_moment("--since", since) if since else None
        end = parse_moment("--until", until) if until else None
        async for record in export_records(sessions, since=start, until=end, tenant=tenant):
            typer.echo(json.dumps(record, ensure_ascii=False))

    run_with_database(action)
