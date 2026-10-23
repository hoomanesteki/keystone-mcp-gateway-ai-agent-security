"""A test-only upstream that returns the API key it received (KS-392).

No demo server does this, and none may: it is in tests/ so that examples/ stays honest. It plays
the upstream that copies a request header into its answer, which is what invariant I3 and the
scrubbing tests need to exist. It requires the key, like the demo servers do, and hands it back in
every shape a result can take: a text block, a nested structure and a block of prose.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from mcp.server.mcpserver import Context, MCPServer

from examples.upstreams import _common
from tests.fixtures.servers import ServerThread

KEY_HEADER = "x-api-key"
NAME = "reflect"


def create_server(extra: str = "") -> MCPServer:
    """`extra` is a second value the server knows and `show_extra` returns. A test registers it
    with the log scrubber to play a secret that Keystone holds for another upstream."""
    server = MCPServer(NAME, log_level="WARNING")

    def received(ctx: Context) -> str:
        return (ctx.headers or {}).get(KEY_HEADER, "")

    @server.tool()
    def show_key(ctx: Context) -> dict[str, Any]:
        """Return the API key this request carried, as a structure (it also becomes the text)."""
        key = received(ctx)
        return {"received": key, "nested": {"headers": [f"X-Api-Key: {key}"]}}

    @server.tool()
    def shout(note: str, ctx: Context) -> str:
        """Return the key inside a sentence."""
        return f"{note}: the key I was sent is {received(ctx)}"

    @server.tool()
    def show_extra() -> dict[str, str]:
        """Return the second value this server knows."""
        return {"extra": extra}

    return server


@contextmanager
def reflecting_upstream(api_key: str, extra: str = "") -> Iterator[ServerThread]:
    """Serve the reflecting upstream on a free port. It answers 401 without `api_key`."""
    app = _common.http_app(create_server(extra), api_key=api_key, host="127.0.0.1")
    thread = ServerThread(app).start()
    try:
        yield thread
    finally:
        thread.stop()
