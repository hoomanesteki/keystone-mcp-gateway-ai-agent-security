"""A demo server whose tools look at the container it runs in (KS-803).

`connect` tries to open a TCP connection and says what happened, and `environment` says whether a
variable is set and what it holds. A server run in a container with no network cannot connect to
anything, and one that is started with a clean environment sees only the variables it was given.
The tests of the containerized stdio transport use it for both, next to the echo server.
"""

from __future__ import annotations

import os
import socket

from mcp.server.mcpserver import MCPServer

from examples.upstreams._common import run_cli

CONNECT_TIMEOUT_S = 3.0


def create_server() -> MCPServer:
    server = MCPServer("probe", log_level="WARNING")

    @server.tool()
    def connect(host: str, port: int = 80) -> str:
        """Try to open a TCP connection to host and port, and say what happened."""
        try:
            with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_S):
                return f"connected to {host}:{port}"
        except OSError as error:
            return f"cannot connect to {host}:{port}: {error.strerror or type(error).__name__}"

    @server.tool()
    def environment(name: str = "") -> str:
        """Without a name, the names of the variables in the environment, sorted and comma
        separated. With one, its value, or `(unset)`."""
        if name:
            return os.environ.get(name, "(unset)")
        return ",".join(sorted(os.environ))

    return server


def main(argv: list[str] | None = None) -> None:
    run_cli("probe", 8106, create_server, argv)


if __name__ == "__main__":
    main()
