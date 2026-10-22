from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from keystone import __version__
from keystone.db.session import create_engine, make_sessionmaker
from keystone.db.tenants import upsert_tenants
from keystone.health import check_dependencies
from keystone.settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # The engine connects lazily, so an app with no tenants starts without Postgres.
        engine = create_engine(settings.database_url.get_secret_value())
        app.state.engine = engine
        app.state.sessionmaker = make_sessionmaker(engine)
        try:
            await upsert_tenants(app.state.sessionmaker, settings.tenants)
            yield
        finally:
            await engine.dispose()

    app = FastAPI(title="Keystone", version=__version__, lifespan=lifespan)
    app.state.settings = settings

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
