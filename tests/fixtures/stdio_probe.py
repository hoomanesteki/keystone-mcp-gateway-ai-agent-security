"""A small MCP server for stdio tests. It reports its process id and its environment.

Run as `python tests/fixtures/stdio_probe.py`. It imports only the SDK, so it starts from any
working directory.
"""

import json
import os

from mcp.server.mcpserver import MCPServer

server = MCPServer("probe", log_level="WARNING")


@server.tool()
def pid() -> int:
    """The process id of this server."""
    return os.getpid()


@server.tool()
def env() -> str:
    """This server's environment as a JSON object."""
    return json.dumps(dict(os.environ))


if __name__ == "__main__":
    server.run("stdio")
