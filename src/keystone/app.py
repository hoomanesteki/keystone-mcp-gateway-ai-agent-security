from fastapi import FastAPI
from fastapi.responses import JSONResponse

from keystone import __version__
from keystone.health import check_dependencies
from keystone.settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="Keystone", version=__version__)
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
