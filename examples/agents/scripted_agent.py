"""A deterministic agent: it connects to an MCP server and runs the steps of a YAML script.

    python -m examples.agents.scripted_agent --url http://localhost:8080/mcp --script demo.yaml

A script is a list of steps. A step is either `list_tools: true` or a call:

    - tool: bank__get_balance
      args: {account: CHK-001}
      expect_error_code: KS_DENIED     # optional: the step passes only if Keystone refuses it so

The agent never decides anything. Tests use it as the baseline every later phase is compared to.
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
from typing import Any

import anyio
import httpx2
import yaml
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

TOKEN_ENV = "KEYSTONE_TOKEN"  # noqa: S105 - the name of the variable, not a token
CALL_ID_KEY = "keystone/call_id"
CODE_KEY = "keystone/code"
CODE_IN_TEXT = re.compile(r"^\[keystone:(KS_[A-Z_]+)\]")
TIMEOUT_S = 60.0
TEXT_PREVIEW = 120


class ScriptError(ValueError):
    """The script file is not a valid script."""


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


async def run_script(url: str, steps: Sequence[Step], token: str | None = None) -> Transcript:
    """Run the steps in order over one MCP session. A step that fails is recorded, and the
    script goes on, so a transcript always shows every step."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    transcript = Transcript()
    http = httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(TIMEOUT_S))
    async with http, Client(streamable_http_client(url, http_client=http)) as client:
        for index, step in enumerate(steps, start=1):
            with anyio.fail_after(TIMEOUT_S):
                transcript.entries.append(await _run_step(client, index, step))
    return transcript


async def _run_step(client: Client, index: int, step: Step) -> Entry:
    if step.tool is None:
        names = sorted(t.name for t in (await client.list_tools()).tools)
        return Entry(index, "list_tools", ok=bool(names), tools=names)
    result = await client.call_tool(step.tool, step.args)
    blocks = [b.model_dump(by_alias=True, mode="json", exclude_none=True) for b in result.content]
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
        arguments=step.args,
        is_error=result.is_error,
        error_code=code,
        call_id=(result.meta or {}).get(CALL_ID_KEY),
        text=text if len(text) <= TEXT_PREVIEW else text[:TEXT_PREVIEW] + "...",
        content=blocks,
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
