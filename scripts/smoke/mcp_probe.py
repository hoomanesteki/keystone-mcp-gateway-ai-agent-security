"""A small MCP client for the smoke scripts: list the tools Keystone offers, or make one call.

    uv run python scripts/smoke/mcp_probe.py list
    uv run python scripts/smoke/mcp_probe.py call bank__get_balance '{"account": "CHK-001"}'

`list` prints `tools: N` and then one name per line. `call` prints one line,
`error=<true|false> code=<keystone code or -> ms=<time of the call>`, then the first text block.
The URL comes from KEYSTONE_URL (default http://localhost:8080/mcp) and the bearer token from
KEYSTONE_TOKEN. The exit code is 0 whenever Keystone answered, whatever the answer was; 2 means it
could not be reached.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
import httpx2
import mcp_types as types
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

CODE_KEY = "keystone/code"
TOKEN_ENV = "KEYSTONE_TOKEN"  # noqa: S105 - the name of the variable, not a token
TIMEOUT_S = 30.0


@asynccontextmanager
async def connect(url: str) -> AsyncIterator[Client]:
    token = os.environ.get(TOKEN_ENV)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    http = httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(TIMEOUT_S))
    async with http, Client(streamable_http_client(url, http_client=http)) as client:
        yield client


async def list_tools(url: str) -> None:
    async with connect(url) as client:
        tools = (await client.list_tools()).tools
    print(f"tools: {len(tools)}")
    for tool in sorted(tools, key=lambda t: t.name):
        print(tool.name)


async def call_tool(url: str, name: str, arguments: dict[str, Any]) -> None:
    async with connect(url) as client:
        started = time.perf_counter()
        result = await client.call_tool(name, arguments)
        elapsed_ms = (time.perf_counter() - started) * 1000
    code = (result.meta or {}).get(CODE_KEY, "-")
    print(f"error={str(result.is_error).lower()} code={code} ms={elapsed_ms:.1f}")
    for block in result.content:
        if isinstance(block, types.TextContent):
            print(block.text.splitlines()[0] if block.text else "")
            break


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    call = commands.add_parser("call")
    call.add_argument("tool")
    call.add_argument("arguments", nargs="?", default="{}", help="a JSON object")
    args = parser.parse_args(argv)
    url = os.environ.get("KEYSTONE_URL", "http://localhost:8080/mcp")

    async def run() -> None:
        with anyio.fail_after(TIMEOUT_S):
            if args.command == "list":
                await list_tools(url)
            else:
                await call_tool(url, args.tool, json.loads(args.arguments))

    try:
        anyio.run(run)
    except Exception as exc:
        print(f"cannot reach Keystone at {url} ({type(exc).__name__})", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
