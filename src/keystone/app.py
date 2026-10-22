from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any

import anyio
import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from keystone import __version__
from keystone.audit.sink import InMemoryAuditSink
from keystone.db.session import create_engine, make_sessionmaker
from keystone.db.tenants import upsert_tenants
from keystone.gateway.dispatch import UpstreamDispatcher
from keystone.gateway.pipeline import AuditSink, Dispatcher, Interceptor
from keystone.gateway.server import Gateway, mount_mcp
from keystone.gateway.sessions import InMemorySessionStore
from keystone.gateway.upstreams import UpstreamDirectory, UpstreamPool, directory_client_factory
from keystone.gateway.wiring import PipelineDeps, build_pipeline
from keystone.health import check_dependencies
from keystone.registry.config import apply_config_upstreams, tool_overrides
from keystone.registry.repo import ToolRepo, UpstreamRepo
from keystone.registry.service import RegistryService
from keystone.registry.sync import RegistrySyncer
from keystone.settings import Settings

log = structlog.get_logger()


def create_app(
    settings: Settings | None = None,
    *,
    audit: AuditSink | None = None,
    interceptors: dict[str, Interceptor] | None = None,
    wrap_dispatcher: Callable[[Dispatcher], Dispatcher] | None = None,
) -> FastAPI:
    """Build the app. The keyword arguments are seams for tests: a different audit sink, a
    real interceptor in one slot, or a spy around the dispatcher."""
    settings = settings or Settings()
    # The engine connects lazily, so building it needs no database. The lifespan disposes it.
    engine = create_engine(settings.database_url.get_secret_value())
    sessions = make_sessionmaker(engine)
    directory = UpstreamDirectory()
    pool = UpstreamPool(directory_client_factory(directory))
    syncer = RegistrySyncer(
        UpstreamRepo(sessions),
        ToolRepo(sessions),
        pool,
        directory,
        overrides=tool_overrides(settings.upstreams),
        timeout_s=settings.registry.sync_timeout_s,
    )
    registry = RegistryService(syncer, cache_ttl_s=settings.registry.cache_ttl_s)
    audit = audit or InMemoryAuditSink()
    dispatcher: Dispatcher = UpstreamDispatcher(pool)
    if wrap_dispatcher is not None:
        dispatcher = wrap_dispatcher(dispatcher)
    pipeline = build_pipeline(settings, PipelineDeps(dispatcher, audit), interceptors)
    gateway = Gateway(settings, registry, InMemorySessionStore(), pipeline)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            await upsert_tenants(sessions, settings.tenants)
            # A config the registry cannot use (unknown tenant, a URL the SSRF guard refuses)
            # stops startup: serving with some upstreams silently missing is worse.
            await apply_config_upstreams(
                UpstreamRepo(sessions),
                settings.upstreams,
                [t.id for t in settings.tenants],
                allow_private=settings.allow_private_upstreams,
            )
            # One task enters and leaves the pool, the sync loop and the session manager, as
            # the SDK's cancel scopes require (engineering note 1).
            async with AsyncExitStack() as stack:
                await stack.enter_async_context(pool)
                # An upstream that is down now gets an error in its report and in `last_error`,
                # and the periodic sync tries it again. It does not stop startup.
                for report in await registry.sync_all():
                    log.info("startup_sync", **report.model_dump())
                await stack.enter_async_context(background_sync(registry, settings))
                await stack.enter_async_context(manager.run())
                yield
        finally:
            await engine.dispose()

    app = FastAPI(title="Keystone", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = sessions
    app.state.registry = registry
    app.state.gateway = gateway
    app.state.audit = audit
    manager = mount_mcp(app, gateway)

    if settings.env != "prod" and isinstance(audit, InMemoryAuditSink):
        sink = audit

        @app.get("/_dev/audit")
        async def dev_audit() -> dict[str, Any]:
            """How many calls the in-memory audit sink holds, for the Phase 1 demo. The admin API
            replaces it in Phase 5. It is not mounted in prod."""
            recent = sink.records[-50:]
            return {
                "count": len(sink.records),
                "recent": [
                    {"call_id": r["call_id"], "tool": r["tool"], "outcome": r["outcome"]}
                    for r in recent
                ],
            }

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        results = await check_dependencies(settings)
        ready = all(results.values())
        body = {
            "status": "ok" if ready else "unavailable",
            "dependencies": {name: "ok" if up else "unavailable" for name, up in results.items()},
        }
        return JSONResponse(body, status_code=200 if ready else 503)

    return app


@asynccontextmanager
async def background_sync(registry: RegistryService, settings: Settings) -> AsyncIterator[None]:
    """Run the periodic sync while the body of the `with` runs. Does nothing when the interval
    is 0."""
    interval = settings.registry.sync_interval_s
    if interval <= 0:
        yield
        return
    async with anyio.create_task_group() as group:
        group.start_soon(registry.run_periodic, interval)
        try:
            yield
        finally:
            group.cancel_scope.cancel()
