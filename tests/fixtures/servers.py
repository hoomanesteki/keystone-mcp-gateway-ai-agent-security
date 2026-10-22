"""Run an ASGI app with uvicorn in a background thread.

The thread has its own event loop, so a test server never shares a loop with pytest-asyncio
(engineering note 3). Port 0 asks the kernel for a free port, which is read back once the
server reports it has started, so two test runs never collide.
"""

import socket
import threading
import time
from collections.abc import Callable
from typing import Self

import uvicorn
from starlette.types import ASGIApp

START_TIMEOUT_S = 10.0
STOP_TIMEOUT_S = 10.0


class ServerThread:
    def __init__(self, app: ASGIApp, *, host: str = "127.0.0.1", port: int = 0) -> None:
        # An open SSE stream would hold a graceful shutdown forever, so cap it.
        config = uvicorn.Config(
            app, host=host, port=port, log_level="warning", timeout_graceful_shutdown=2
        )
        self.server = uvicorn.Server(config)
        self.host = host
        self._thread = threading.Thread(target=self.server.run, name="test-server", daemon=True)
        self._stopped = False

    def start(self) -> Self:
        self._thread.start()
        deadline = time.monotonic() + START_TIMEOUT_S
        while not self.server.started:
            if not self._thread.is_alive():
                raise RuntimeError("test server exited before it started")
            if time.monotonic() > deadline:
                raise TimeoutError("test server did not start in time")
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        self.server.should_exit = True
        self._thread.join(STOP_TIMEOUT_S)
        if self._thread.is_alive():
            raise TimeoutError("test server did not stop in time")

    @property
    def port(self) -> int:
        port: int = self.server.servers[0].sockets[0].getsockname()[1]
        return port

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


def free_port() -> int:
    """A port nothing listens on now. Another process could take it before the caller does, which
    is acceptable in a test."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


class RestartableServer:
    """A server on a fixed port that a test can stop and start again, to play an upstream that
    goes down and comes back. `make_app` builds a new app on every start (engineering note 2)."""

    def __init__(self, make_app: Callable[[], ASGIApp], *, port: int | None = None) -> None:
        self._make_app = make_app
        self.port = port or free_port()
        self._thread: ServerThread | None = None

    @property
    def url(self) -> str:
        """The MCP endpoint."""
        return f"http://127.0.0.1:{self.port}/mcp"

    @property
    def running(self) -> bool:
        return self._thread is not None

    def start(self) -> Self:
        if self._thread is None:
            self._thread = ServerThread(self._make_app(), port=self.port).start()
        return self

    def stop(self) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.stop()
