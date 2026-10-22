from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager

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
from keystone.gateway.upstreams import UpstreamPool, http_client_factory
from keystone.gateway.wiring import PipelineDeps, build_pipeline
from keystone.health import check_dependencies
from keystone.registry.static import StaticRegistry
from keystone.settings import Settings


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
    urls = {u.id: u.url for u in settings.upstreams if u.transport == "http" and u.url}
    pool = UpstreamPool(http_client_factory(urls))
    registry = StaticRegistry()
    audit = audit or InMemoryAuditSink()
    dispatcher: Dispatcher = UpstreamDispatcher(pool)
    if wrap_dispatcher is not None:
        dispatcher = wrap_dispatcher(dispatcher)
    pipeline = build_pipeline(settings, PipelineDeps(dispatcher, audit), interceptors)
    gateway = Gateway(settings, registry, InMemorySessionStore(), pipeline)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # The engine connects lazily, so an app with no tenants starts without Postgres.
        engine = create_engine(settings.database_url.get_secret_value())
        app.state.engine = engine
        app.state.sessionmaker = make_sessionmaker(engine)
        try:
            await upsert_tenants(app.state.sessionmaker, settings.tenants)
            # One task enters and leaves the pool and the session manager, as the SDK's
            # cancel scopes require (engineering note 1).
            async with AsyncExitStack() as stack:
                await stack.enter_async_context(pool)
                await registry.load(pool, settings.upstreams)
                await stack.enter_async_context(manager.run())
                yield
        finally:
            await engine.dispose()

    app = FastAPI(title="Keystone", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.gateway = gateway
    app.state.audit = audit
    manager = mount_mcp(app, gateway)

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
