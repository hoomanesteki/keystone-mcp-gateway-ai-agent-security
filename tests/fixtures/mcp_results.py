"""Small readers for MCP results, shared by the integration tests."""

import json
from typing import Any

import mcp_types as types


def texts(result: types.CallToolResult) -> list[str]:
    return [block.text for block in result.content if isinstance(block, types.TextContent)]


def one(result: types.CallToolResult) -> Any:
    """The JSON of a tool that returns one object."""
    [text] = texts(result)
    return json.loads(text)


def many(result: types.CallToolResult) -> list[Any]:
    """The JSON of a tool that returns a list: the server sends one text block per item."""
    return [json.loads(text) for text in texts(result)]
