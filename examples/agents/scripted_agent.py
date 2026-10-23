"""A deterministic agent: it connects to an MCP server and runs the steps of a YAML script.

    python -m examples.agents.scripted_agent --url http://localhost:8080/mcp --script demo.yaml

A script is a list of steps. A step is either `list_tools: true` or a call:

    - tool: bank__get_balance
      args: {account: CHK-001}
      expect_error_code: KS_DENIED     # optional: the step passes only if Keystone refuses it so

The agent never decides anything. Tests use it as the baseline every later phase is compared to.

Approvals (Phase 6). A call that needs a person's approval is held by Keystone and, if nobody
decides in time, answered with KS_APPROVAL_PENDING and an id. The agent then calls
`keystone__await_approval` once with that id, and the step reports what the await returned. A step
that expects KS_APPROVAL_PENDING is not waited for: it passes on the pending answer. A step that
calls `keystone__await_approval` without an `approval_id` waits for the approval the agent was last
told about and has not seen decided; with none outstanding it passes and says so.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

import anyio
import httpx2
import mcp_types as types
import yaml
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

TOKEN_ENV = "KEYSTONE_TOKEN"  # noqa: S105 - the name of the variable, not a token
CALL_ID_KEY = "keystone/call_id"
CODE_KEY = "keystone/code"
APPROVAL_ID_KEY = "keystone/approval_id"
CODE_IN_TEXT = re.compile(r"^\[keystone:(KS_[A-Z_]+)\]")
AWAIT_TOOL = "keystone__await_approval"
PENDING_CODE = "KS_APPROVAL_PENDING"
# Keystone holds a call that needs approval for approvals.wait_seconds, at most 300, and the await
# tool for at most 120. A client that gives up sooner would give up on a call that is only waiting.
CALL_TIMEOUT_S = 330.0
TEXT_PREVIEW = 120


class ScriptError(ValueError):
    """The script file is not a valid script."""


class ToolClient(Protocol):
    """The two things of an MCP client that the agent uses, so a test can stand in for it."""

    async def list_tools(self) -> types.ListToolsResult: ...

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult: ...


@dataclass(frozen=True)
class Step:
    tool: str | None = None  # None means: list the tools
    args: dict[str, Any] = field(default_factory=dict)
    expect_error_code: str | None = None


@dataclass
class Entry:
    index: int
    kind: str  # "list_tools" or "call_tool"
    ok: bool
    tool: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    is_error: bool = False
    error_code: str | None = None
    call_id: str | None = None
    text: str = ""
    content: list[dict[str, Any]] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    # The approval this step waited for on its own, after Keystone answered KS_APPROVAL_PENDING.
    awaited: str | None = None


@dataclass
class Transcript:
    entries: list[Entry] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(entry.ok for entry in self.entries)

    @property
    def calls(self) -> list[Entry]:
        return [e for e in self.entries if e.kind == "call_tool"]

    def json_lines(self) -> list[str]:
        """One JSON object per step, without the raw content blocks."""
        return [json.dumps(_summary(e), sort_keys=True) for e in self.entries]

    def text(self) -> str:
        rows = []
        for e in self.entries:
            mark = "ok  " if e.ok else "FAIL"
            if e.kind == "list_tools":
                shown = ", ".join(e.tools[:4]) + (" ..." if len(e.tools) > 4 else "")
                rows.append(f"{e.index}. {mark} list tools: {len(e.tools)} tools ({shown})")
                continue
            args = json.dumps(e.arguments, sort_keys=True)
            result = f"{e.error_code or 'error'}: {e.text}" if e.is_error else e.text
            rows.append(f"{e.index}. {mark} {e.tool} {args}")
            if e.awaited:
                rows.append(f"      (answered {PENDING_CODE}; waited for approval {e.awaited})")
            rows.append(f"      -> {result}")
            if e.call_id:
                rows.append(f"      call_id {e.call_id}")
        return "\n".join(rows)


def _summary(entry: Entry) -> dict[str, Any]:
    data = asdict(entry)
    data.pop("content")
    return data


def load_steps(path: Path) -> list[Step]:
    document = yaml.safe_load(path.read_text())
    items = document.get("steps") if isinstance(document, dict) else document
    if not isinstance(items, list) or not items:
        raise ScriptError(f"{path}: expected a list of steps (or a 'steps' list)")
    steps = []
    for number, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise ScriptError(f"{path}: step {number} is not a mapping")
        unknown = set(item) - {"tool", "args", "expect_error_code", "list_tools"}
        if unknown:
            raise ScriptError(f"{path}: step {number} has unknown keys {sorted(unknown)}")
        if item.get("list_tools"):
            steps.append(Step())
            continue
        if not isinstance(item.get("tool"), str):
            raise ScriptError(f"{path}: step {number} needs a 'tool' or 'list_tools: true'")
        args = item.get("args") or {}
        if not isinstance(args, dict):
            raise ScriptError(f"{path}: step {number} 'args' must be a mapping")
        steps.append(Step(item["tool"], args, item.get("expect_error_code")))
    return steps


def _error_code(blocks: list[dict[str, Any]]) -> str | None:
    if not blocks:
        return None
    meta = blocks[0].get("_meta") or {}
    if CODE_KEY in meta:
        return str(meta[CODE_KEY])
    match = CODE_IN_TEXT.match(str(blocks[0].get("text", "")))
    return match.group(1) if match else None


def _blocks(result: types.CallToolResult) -> list[dict[str, Any]]:
    return [b.model_dump(by_alias=True, mode="json", exclude_none=True) for b in result.content]


def _code(result: types.CallToolResult) -> str | None:
    return _error_code(_blocks(result)) if result.is_error else None


def _approval_id(result: types.CallToolResult) -> str | None:
    """The id of the request Keystone is holding, from the result's `_meta` or the block's."""
    found = (result.meta or {}).get(APPROVAL_ID_KEY)
    if found is None:
        blocks = _blocks(result)
        found = (blocks[0].get("_meta") or {}).get(APPROVAL_ID_KEY) if blocks else None
    return str(found) if found else None


async def run_script(url: str, steps: Sequence[Step], token: str | None = None) -> Transcript:
    """Run the steps in order over one MCP session. A step that fails is recorded, and the
    script goes on, so a transcript always shows every step."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    transcript = Transcript()
    outstanding = Outstanding()
    http = httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(CALL_TIMEOUT_S))
    async with http, Client(streamable_http_client(url, http_client=http)) as client:
        for index, step in enumerate(steps, start=1):
            # A step can be a call and the wait for its approval, so it may take twice as long.
            with anyio.fail_after(2 * CALL_TIMEOUT_S):
                transcript.entries.append(await run_step(client, index, step, outstanding))
    return transcript


@dataclass
class Outstanding:
    """The approval the agent was last told to wait for and has not seen decided."""

    approval_id: str | None = None


async def settle_pending(
    client: ToolClient, result: types.CallToolResult
) -> tuple[types.CallToolResult, str | None]:
    """If Keystone answered KS_APPROVAL_PENDING, wait for that approval once with
    keystone__await_approval and return what the wait returned, with the id waited for. Any other
    answer comes back as it is, with None. The naive agent of Phase 7 reacts the same way."""
    approval_id = _approval_id(result)
    if _code(result) == PENDING_CODE and approval_id:
        return await client.call_tool(AWAIT_TOOL, {"approval_id": approval_id}), approval_id
    return result, None


async def run_step(client: ToolClient, index: int, step: Step, outstanding: Outstanding) -> Entry:
    if step.tool is None:
        names = sorted(t.name for t in (await client.list_tools()).tools)
        return Entry(index, "list_tools", ok=bool(names), tools=names)
    arguments = dict(step.args)
    if step.tool == AWAIT_TOOL and "approval_id" not in arguments:
        if outstanding.approval_id is None:
            return Entry(
                index,
                "call_tool",
                ok=True,
                tool=step.tool,
                text="no approval is waiting, so there is nothing to wait for",
            )
        arguments["approval_id"] = outstanding.approval_id
    result = await client.call_tool(step.tool, arguments)
    awaited: str | None = None
    if step.tool != AWAIT_TOOL:
        if _code(result) == PENDING_CODE:
            outstanding.approval_id = _approval_id(result)
        if step.expect_error_code != PENDING_CODE:
            # Once. A second wait is the script's to ask for, with a step of its own.
            result, awaited = await settle_pending(client, result)
    if _code(result) == PENDING_CODE:
        outstanding.approval_id = _approval_id(result) or outstanding.approval_id
    elif step.tool == AWAIT_TOOL or awaited:
        outstanding.approval_id = None  # decided, one way or the other
    blocks = _blocks(result)
    code = _error_code(blocks) if result.is_error else None
    if step.expect_error_code is None:
        ok = not result.is_error
    else:
        ok = result.is_error and code == step.expect_error_code
    text = " ".join(str(b.get("text", "")) for b in blocks if b.get("type") == "text")
    text = " ".join(text.split())
    return Entry(
        index,
        "call_tool",
        ok=ok,
        tool=step.tool,
        arguments=arguments,
        is_error=result.is_error,
        error_code=code,
        call_id=(result.meta or {}).get(CALL_ID_KEY),
        text=text if len(text) <= TEXT_PREVIEW else text[:TEXT_PREVIEW] + "...",
        content=blocks,
        awaited=awaited,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a script of MCP tool calls")
    parser.add_argument(
        "--url", required=True, help="MCP endpoint, for example http://localhost:8080/mcp"
    )
    parser.add_argument("--script", required=True, type=Path, help="YAML file with the steps")
    parser.add_argument(
        "--token", default=os.environ.get(TOKEN_ENV), help=f"bearer token (or ${TOKEN_ENV})"
    )
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args(argv)

    transcript = asyncio.run(run_script(args.url, load_steps(args.script), args.token))
    print(transcript.text() if args.format == "text" else "\n".join(transcript.json_lines()))
    return 0 if transcript.ok else 1


if __name__ == "__main__":
    sys.exit(main())
