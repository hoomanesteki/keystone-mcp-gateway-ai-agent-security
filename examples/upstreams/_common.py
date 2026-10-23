"""Pieces shared by the demo upstream servers.

Each server is `python -m examples.upstreams.<name>_server --port N --transport http|stdio`.
The HTTP form adds three plain routes next to /mcp that are not tools, so an agent cannot call
them: GET /healthz, POST /_reset (back to the seed) and GET /_state (what the server did). When a
server requires an API key, /_state also says, as a boolean, whether a request with the right key
has arrived since the last reset. It never shows the key, and no tool or route returns it.
"""

from __future__ import annotations

import argparse
import hmac
import os
import sqlite3
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from weakref import WeakKeyDictionary

import uvicorn
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
API_KEY_HEADER = "x-api-key"


@dataclass
class KeyProbe:
    """Whether a request with the right API key has reached /mcp since the last reset."""

    received: bool = False


# One probe per server, made when its test routes are registered and read by `http_app`, so the
# servers' create_server functions need no extra argument.
_PROBES: WeakKeyDictionary[MCPServer, KeyProbe] = WeakKeyDictionary()


class ApiKeyMiddleware:
    """Require `X-Api-Key` on /mcp when the server has a key. The test routes stay open."""

    def __init__(self, app: ASGIApp, api_key: str, probe: KeyProbe | None = None) -> None:
        self.app = app
        self.api_key = api_key
        self.probe = probe

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"].startswith("/mcp"):
            headers = dict(scope["headers"])
            given = headers.get(API_KEY_HEADER.encode(), b"").decode("latin-1")
            if not hmac.compare_digest(given.encode(), self.api_key.encode()):
                response = JSONResponse({"error": "invalid or missing X-Api-Key"}, status_code=401)
                await response(scope, receive, send)
                return
            if self.probe is not None:
                self.probe.received = True
        await self.app(scope, receive, send)


class CallLog:
    """Server middleware that records the name of every tools/call, for /_state."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def __call__(self, ctx: ServerRequestContext[Any, Any], call_next: Any) -> Any:
        if ctx.method == "tools/call" and ctx.params:
            self.calls.append(str(ctx.params.get("name")))
        return await call_next(ctx)


class Database:
    """A SQLite file. Every call opens its own connection, so threads never share one."""

    def __init__(self, path: Path | None, name: str) -> None:
        self.path = path or Path(tempfile.mkdtemp(prefix=f"keystone-{name}-")) / f"{name}.db"

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            with con:  # commit on success, roll back on error
                yield con
        finally:
            con.close()


def register_test_routes(
    server: MCPServer,
    reset: Callable[[], None],
    state: Callable[[], dict[str, Any]],
) -> None:
    probe = _PROBES.setdefault(server, KeyProbe())

    @server.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    @server.custom_route("/_reset", methods=["POST"])
    async def reset_route(request: Request) -> Response:
        reset()
        probe.received = False
        return JSONResponse({"status": "reset"})

    @server.custom_route("/_state", methods=["GET"])
    async def state_route(request: Request) -> Response:
        return JSONResponse({**state(), "api_key_received": probe.received})


def http_app(server: MCPServer, *, api_key: str | None, host: str) -> Starlette:
    # The SDK turns on DNS rebinding protection only for a loopback host. In a container the
    # server binds 0.0.0.0 and other containers reach it by service name.
    app = server.streamable_http_app(host=host)
    if api_key:
        app.add_middleware(ApiKeyMiddleware, api_key=api_key, probe=_PROBES.get(server))
    return app


def run_cli(
    name: str,
    default_port: int,
    create_server: Callable[[], MCPServer],
    argv: Sequence[str] | None = None,
) -> None:
    parser = argparse.ArgumentParser(prog=f"{name}_server", description=f"Demo {name} MCP server")
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--transport", choices=["http", "stdio"], default="http")
    args = parser.parse_args(argv)

    server = create_server()
    if args.transport == "stdio":
        server.run("stdio")
        return
    # <NAME>_API_KEY unset means no check. Phase 3 turns it on in compose.
    api_key = os.environ.get(f"{name.upper()}_API_KEY") or None
    uvicorn.run(
        http_app(server, api_key=api_key, host=args.host),
        host=args.host,
        port=args.port,
        log_level="warning",
    )
