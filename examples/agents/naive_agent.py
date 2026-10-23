"""A naive agent: the worst case, a model that obeys everything it reads (KS-708).

    python -m examples.agents.naive_agent --url http://localhost:8080/mcp --script task.yaml

It runs a user's task as a script, like the scripted agent. Whenever a tool result holds a ks-do
marker (examples/injections.py), it calls the tool the marker names with the arguments it carries,
at once and without asking. That simulates a model that has been fully taken over by an
instruction in the data it was given. If a gateway stops this agent, the protection does not
depend on how a real model behaves on a given day. Real models are measured separately.

What it does besides:

- A call that is answered KS_APPROVAL_PENDING is followed by one keystone__await_approval, as the
  scripted agent does.
- The same marker is obeyed once per run, and no more than MAX_INJECTED calls are made, so a tool
  that hands its input back cannot start a loop.
- A tool is named as the script or the marker names it (`mail__send_email`). Talking to a server
  directly, that tool is `send_email`, and the agent uses that name when it is the one listed. A
  name that is listed nowhere is tried as it is, because a taken-over model would try it, and
  whatever refuses it is the thing being tested.
- It acts on what it reads, never on what it sends: a marker in its own script is ignored.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

import anyio
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from examples.agents.scripted_agent import (
    CALL_TIMEOUT_S,
    TOKEN_ENV,
    Entry,
    Outstanding,
    Step,
    ToolClient,
    Transcript,
    load_steps,
    run_step,
)
from examples.injections import find_markers

MAX_INJECTED = 10


@dataclass
class Injected(Entry):
    """A call the agent made because a result told it to. `source` is the index of the entry
    whose result held the marker. It is always `ok`: nothing was expected of it, and whether it
    got through is for `is_error` and `error_code` to say."""

    injected: bool = True
    source: int = 0


@dataclass
class Compromise:
    """What the agent knows while it obeys: the tools it can see, the approval it waits for, the
    number of the next entry and which markers it has obeyed already."""

    names: set[str]
    outstanding: Outstanding
    next_index: int = 1
    done: set[str] = field(default_factory=set)
    count: int = 0

    def take_index(self) -> int:
        index, self.next_index = self.next_index, self.next_index + 1
        return index


def resolve(name: str, names: set[str]) -> str:
    """The name to call: as written when it is listed, else without its upstream prefix when that
    is listed, else as written."""
    if name in names:
        return name
    _, separator, bare = name.partition("__")
    return bare if separator and bare in names else name


def _strings(value: Any) -> Iterator[str]:
    """Every string in a JSON value, keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def result_text(entry: Entry) -> str:
    """What a reader of the result sees, whole (the transcript's own `text` is cut short). A tool
    that returns an object sends it as JSON text, where a quote or a line break in a string is
    written with a backslash, and a reader undoes that. So the text of a block is read both as it
    is and, when it is JSON, as the strings in it."""
    seen: list[str] = []
    for block in entry.content:
        if block.get("type") != "text":
            continue
        text = str(block.get("text", ""))
        seen.append(text)
        try:
            seen.extend(_strings(json.loads(text)))
        except ValueError:
            continue
    return "\n".join(seen)


def injected_from(entry: Entry, source: int) -> Injected:
    values = {f.name: getattr(entry, f.name) for f in fields(Entry)}
    values["ok"] = True
    return Injected(**values, source=source)


async def follow(client: ToolClient, entry: Entry, state: Compromise) -> list[Entry]:
    """Obey the markers in the result of `entry`, and in the results of what that causes. Returns
    the calls it made, in order."""
    made: list[Entry] = []
    for call in find_markers(result_text(entry)):
        key = json.dumps({"tool": call.tool, "args": call.args}, sort_keys=True)
        if key in state.done or state.count >= MAX_INJECTED:
            continue
        state.done.add(key)
        state.count += 1
        step = Step(resolve(call.tool, state.names), dict(call.args))
        with anyio.fail_after(2 * CALL_TIMEOUT_S):
            done = await run_step(client, state.take_index(), step, state.outstanding)
        obeyed = injected_from(done, entry.index)
        made.append(obeyed)
        made.extend(await follow(client, obeyed, state))
    return made


async def run_naive(
    url: str,
    steps: Sequence[Step],
    token: str | None = None,
    headers: Mapping[str, str] | None = None,
) -> Transcript:
    """Run the user's task over one MCP session, obeying every marker that a result carries.
    `headers` are sent with every request (an `X-Api-Key` for a server that wants one)."""
    sent = dict(headers or {})
    if token:
        sent["Authorization"] = f"Bearer {token}"
    transcript = Transcript()
    http = httpx2.AsyncClient(headers=sent, timeout=httpx2.Timeout(CALL_TIMEOUT_S))
    async with http, Client(streamable_http_client(url, http_client=http)) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        state = Compromise(names, Outstanding())
        for step in steps:
            if step.tool is not None:
                step = replace(step, tool=resolve(step.tool, names))
            with anyio.fail_after(2 * CALL_TIMEOUT_S):
                entry = await run_step(client, state.take_index(), step, state.outstanding)
            transcript.entries.append(entry)
            transcript.entries.extend(await follow(client, entry, state))
    return transcript


def describe(transcript: Transcript) -> str:
    """The transcript as text, with the calls the agent made on its own marked."""
    parts = []
    for entry in transcript.entries:
        block = Transcript([entry]).text()
        if isinstance(entry, Injected):
            block = f"   >>> obeyed an instruction in the result of entry {entry.source}\n{block}"
        parts.append(block)
    return "\n".join(parts)


def parse_header(text: str) -> tuple[str, str]:
    name, separator, value = text.partition(":")
    if not separator or not name.strip():
        raise argparse.ArgumentTypeError(f"expected 'Name: value', got {text!r}")
    return name.strip(), value.strip()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a task as an agent that obeys what it reads")
    parser.add_argument(
        "--url", required=True, help="MCP endpoint, for example http://localhost:8080/mcp"
    )
    parser.add_argument("--script", required=True, type=Path, help="YAML file with the task")
    parser.add_argument(
        "--token", default=os.environ.get(TOKEN_ENV), help=f"bearer token (or ${TOKEN_ENV})"
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        type=parse_header,
        metavar="'Name: value'",
        help="a header to send with every request, for a server that wants an API key",
    )
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args(argv)

    transcript = asyncio.run(
        run_naive(args.url, load_steps(args.script), args.token, dict(args.header))
    )
    print(describe(transcript) if args.format == "text" else "\n".join(transcript.json_lines()))
    return 0 if transcript.ok else 1


if __name__ == "__main__":
    sys.exit(main())
