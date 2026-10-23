import os
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AsyncExitStack, asynccontextmanager

import anyio
import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from keystone import __version__
from keystone.admin.api import create_admin_router
from keystone.admin.auth import AdminAuth, AdminRefused, admin_refused_handler
from keystone.audit.sink import PostgresAuditSink
from keystone.db.session import create_engine, make_sessionmaker
from keystone.db.tenants import upsert_tenants
from keystone.gateway.dispatch import UpstreamDispatcher
from keystone.gateway.health import UpstreamHealth
from keystone.gateway.interceptors.policy import MemoryListCache, PolicyToolFilter, RedisListCache
from keystone.gateway.pipeline import AuditSink, Dispatcher, Interceptor
from keystone.gateway.server import Gateway, mount_mcp
from keystone.gateway.session_repo import SessionRepo
from keystone.gateway.sessions import InMemorySessionStore, RedisSessionStore, SessionStore
from keystone.gateway.upstreams import UpstreamDirectory, UpstreamPool, directory_client_factory
from keystone.gateway.wiring import PipelineDeps, build_pipeline
from keystone.health import check_dependencies, upstream_statuses
from keystone.identity.credential_repo import vault_from_settings
from keystone.identity.metadata import add_metadata_route
from keystone.identity.middleware import Authenticator
from keystone.identity.vault import VaultError
from keystone.policy.engine import CedarPolicyEngine
from keystone.policy.schema_info import args_fields
from keystone.policy.store import PolicyStore, reload_on_sighup
from keystone.policy.versions import PolicyVersionRepo
from keystone.registry.config import (
    apply_config_upstreams,
    seed_credentials,
    stdio_environments,
    tool_overrides,
)
from keystone.registry.repo import ToolRepo, UpstreamRepo
from keystone.registry.service import RegistryService
from keystone.registry.sync import RegistrySyncer
from keystone.settings import Settings
from keystone.telemetry.metrics import Metrics

log = structlog.get_logger()


def create_app(
    settings: Settings | None = None,
    *,
    audit: AuditSink | None = None,
    interceptors: dict[str, Interceptor] | None = None,
    wrap_dispatcher: Callable[[Dispatcher], Dispatcher] | None = None,
    environ: Mapping[str, str] | None = None,
) -> FastAPI:
    """Build the app. The keyword arguments are seams for tests: a different audit sink, a
    real interceptor in one slot, a spy around the dispatcher, or the environment that upstream
    credentials are read from (the process environment by default)."""
    settings = settings or Settings()
    # Refuses to build an app whose authentication cannot work, instead of one that answers 401
    # to everybody.
    authenticator = Authenticator(settings)
    # The engine connects lazily, so building it needs no database. The lifespan disposes it.
    engine = create_engine(settings.database_url.get_secret_value())
    sessions = make_sessionmaker(engine)
    vault = vault_from_settings(settings, sessions)
    needing_a_vault = [
        u.id for u in settings.upstreams if u.credential_mode != "none" or u.credential_env
    ]
    if needing_a_vault and vault is None:
        raise VaultError(
            f"upstream {', '.join(needing_a_vault)} uses credentials, "
            "so KEYSTONE_MASTER_KEYS must be set"
        )
    service_headers = vault.service_headers if vault else None
    # The policies are read now, so a missing or invalid set stops startup before anything serves.
    # Reloads later keep the set in force when the new one is refused.
    policies = PolicyStore(
        settings.policy.root,
        [t.id for t in settings.tenants],
        include_demo=settings.policy.include_demo,
        recorder=PolicyVersionRepo(sessions),
    )
    policies.start()
    directory = UpstreamDirectory()
    pool = UpstreamPool(
        directory_client_factory(directory, health_timeout_s=settings.health.timeout_s)
    )
    syncer = RegistrySyncer(
        UpstreamRepo(sessions),
        ToolRepo(sessions),
        pool,
        directory,
        overrides=tool_overrides(settings.upstreams),
        timeout_s=settings.registry.sync_timeout_s,
        environments=stdio_environments(settings.upstreams),
        service_headers=service_headers,
    )
    registry = RegistryService(syncer, cache_ttl_s=settings.registry.cache_ttl_s)
    health = UpstreamHealth(
        pool,
        syncer.upstreams,
        syncer.learn,
        interval_s=settings.health.interval_s,
        timeout_s=settings.health.timeout_s,
        degraded_after=settings.health.degraded_after,
        down_after=settings.health.down_after,
        service_headers=service_headers,
    )
    metrics = Metrics()
    audit = audit or PostgresAuditSink(sessions, metrics=metrics)
    dispatcher: Dispatcher = UpstreamDispatcher(pool, health)
    if wrap_dispatcher is not None:
        dispatcher = wrap_dispatcher(dispatcher)
    policy_engine = CedarPolicyEngine(policies)
    pipeline = build_pipeline(
        settings,
        PipelineDeps(dispatcher, audit, tool_states=registry, vault=vault, policy=policy_engine),
        interceptors,
    )
    # An empty KEYSTONE_REDIS_URL keeps session state in this process, for a single-process setup.
    redis = (
        Redis.from_url(settings.redis_url.get_secret_value(), decode_responses=True)
        if settings.redis_url.get_secret_value()
        else None
    )
    session_store: SessionStore = (
        RedisSessionStore(redis, SessionRepo(sessions)) if redis else InMemorySessionStore()
    )
    tool_filter = PolicyToolFilter(
        policy_engine,
        RedisListCache(redis) if redis else MemoryListCache(),
        ttl_s=settings.policy.list_cache_ttl_s,
    )
    gateway = Gateway(settings, registry, session_store, pipeline, tool_filter)
    registry.add_listener(gateway.notify_tools_changed)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            await upsert_tenants(sessions, settings.tenants)
            await policies.record_current()
            # A config the registry cannot use (unknown tenant, a URL the SSRF guard refuses)
            # stops startup: serving with some upstreams silently missing is worse.
            await apply_config_upstreams(
                UpstreamRepo(sessions),
                settings.upstreams,
                [t.id for t in settings.tenants],
                allow_private=settings.allow_private_upstreams,
                args=args_fields(policies.current.schema.text),
            )
            # Credentials given in the environment go into the vault now, before the first sync
            # needs them.
            if vault is not None:
                await seed_credentials(
                    vault, settings.upstreams, os.environ if environ is None else environ
                )
            # One task enters and leaves the pool, the sync loop and the session manager, as
            # the SDK's cancel scopes require (engineering note 1).
            async with AsyncExitStack() as stack:
                # Entered first, so it is left last: the writer flushes what the calls that were
                # still running when the server stopped have queued.
                if isinstance(audit, PostgresAuditSink):
                    await stack.enter_async_context(audit)
                await stack.enter_async_context(pool)
                # An upstream that is down now gets an error in its report and in `last_error`,
                # and the periodic sync tries it again. It does not stop startup.
                for report in await registry.sync_all():
                    log.info("startup_sync", **report.model_dump())
                await stack.enter_async_context(
                    background_tasks(registry, health, settings, policies)
                )
                await stack.enter_async_context(manager.run())
                yield
        finally:
            if redis is not None:
                await redis.aclose()
            await engine.dispose()

    app = FastAPI(title="Keystone", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = sessions
    app.state.registry = registry
    app.state.health = health
    app.state.gateway = gateway
    app.state.audit = audit
    app.state.metrics = metrics
    app.state.authenticator = authenticator
    app.state.vault = vault
    app.state.policies = policies
    app.add_exception_handler(AdminRefused, admin_refused_handler)
    app.include_router(create_admin_router(AdminAuth(authenticator), policies))
    manager = mount_mcp(app, gateway, authenticator)
    add_metadata_route(app, settings)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        results: dict[str, bool] = {}
        statuses: dict[str, str] = {}

        async def dependencies() -> None:
            results.update(await check_dependencies(settings))

        async def upstreams() -> None:
            statuses.update(await upstream_statuses(syncer.upstreams))

        async with anyio.create_task_group() as group:
            group.start_soon(dependencies)
            group.start_soon(upstreams)
        ready = all(results.values())
        body = {
            "status": "ok" if ready else "unavailable",
            "dependencies": {name: "ok" if up else "unavailable" for name, up in results.items()},
            # An upstream that is down does not make Keystone unready: the others still work.
            "upstreams": dict(sorted(statuses.items())),
        }
        return JSONResponse(body, status_code=200 if ready else 503)

    return app


@asynccontextmanager
async def background_tasks(
    registry: RegistryService, health: UpstreamHealth, settings: Settings, policies: PolicyStore
) -> AsyncIterator[None]:
    """Run the periodic sync (unless its interval is 0), the watch for changes made by other
    processes, the health probes (unless their interval is 0) and the policy reload on SIGHUP
    while the body of the `with` runs."""
    async with anyio.create_task_group() as group:
        group.start_soon(registry.run_watch)
        group.start_soon(reload_on_sighup, policies)
        if settings.registry.sync_interval_s > 0:
            group.start_soon(registry.run_periodic, settings.registry.sync_interval_s)
        if settings.health.interval_s > 0:
            group.start_soon(health.run)
        try:
            yield
        finally:
            group.cancel_scope.cancel()
