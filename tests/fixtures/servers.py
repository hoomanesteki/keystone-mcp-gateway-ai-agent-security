"""Run an ASGI app with uvicorn in a background thread.

The thread has its own event loop, so a test server never shares a loop with pytest-asyncio
(engineering note 3). Port 0 asks the kernel for a free port, which is read back once the
server reports it has started, so two test runs never collide.
"""

import threading
import time
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
