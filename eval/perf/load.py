"""Load a Keystone, or an upstream on its own, with many MCP sessions and time every call (KS-903).

    python -m eval.perf.load --url http://localhost:8080/mcp --tool echo__echo \
        --user olivia --client ops-agent --sessions 200 --calls 20 --size 1024 --out run.json
    python -m eval.perf.load --url http://localhost:8104/mcp --tool echo \
        --header X-Api-Key=<key> --sessions 200 --calls 20 --size 1024

N sessions are opened at once. Each makes M calls of the echo tool one after the other, with a
payload of S bytes of English text, and times each call from the request to the whole answer. The
calls start together, once every session is open and has made a few calls that are not counted
(connections, caches). A call that fails is counted as an error and timed like the others.

The sessions are shared out over several processes, because one Python process that runs 200
clients is itself slow, and a slow client puts its own time into every latency. Each process says
how busy it was (`cpu_s` over `wall_s`), so that a run in which the generator was the limit shows.
A token of the local realm lives five minutes and a run can take longer, so a process that is
given a user gets its own token and a new one every two minutes. The credentials of a target that
is not Keycloak's (an API key) are passed to the processes on their standard input and never in an
argument.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Generator, Mapping
from contextlib import AsyncExitStack
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

import anyio
import httpx2
import mcp_types as types
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from eval.perf.stats import summarize
from examples.agents.scripted_agent import _code

# A paragraph of plain English, repeated to the size asked for. It holds no instruction, so the
# scanner has nothing to find in it, and its words are ordinary ones, so that a byte costs the
# model about what it costs on a real document.
PARAGRAPH = (
    "The support team closed twelve tickets last week, most of them about the new invoice layout. "
    "Customers asked where to find the payment reference, and two wanted the report in another "
    "format. The next release moves the reference to the top of the page and adds a column for "
    "the purchase order. Please read the notes below and send your comments before Friday, so "
    "that the changes can be reviewed on Monday morning with the finance and the sales teams. "
)
READY = "ready"
GO = "go"
CALL_TIMEOUT_S = 120.0
# A run that has lasted this long stops making calls.
MAX_RUN_S = 600.0
# A token of the local realm lives 300 s.
REFRESH_S = 120.0
# Opening 200 sessions and making their calls that are not counted, through a gateway that
# answers ten calls a second, takes minutes.
SETUP_TIMEOUT_S = 600.0


class Bearer(httpx2.Auth):
    """The token of every request of a process. It is a value that can change, so that a token
    that is about to run out can be replaced for the sessions that are open."""

    def __init__(self, token: str) -> None:
        self.token = token

    def auth_flow(
        self, request: httpx2.Request
    ) -> Generator[httpx2.Request, httpx2.Response, None]:
        request.headers["Authorization"] = f"Bearer {self.token}"
        yield request


def fetch_token(user: str, client: str) -> str:
    from examples.agents.auto_reject import token_from_script

    return token_from_script(user, client)


async def keep_fresh(bearer: Bearer, user: str, client: str) -> None:
    """Replace the token every `REFRESH_S`, for as long as the run lasts."""
    while True:
        await anyio.sleep(REFRESH_S)
        bearer.token = await anyio.to_thread.run_sync(fetch_token, user, client)


TAG = re.compile(r"^\[keystone:(KS_[A-Z_]+)\]\s*(.*)", re.DOTALL)
# The id Keystone puts in a message ("call 01M5... denied: ..."), which differs in every one.
CALL_ID = re.compile(r"\bcall [0-9A-Z]{26}\s*")


def error_kind(result: types.CallToolResult) -> str:
    """What a failed call is counted as: Keystone's code and the start of its message, such as
    `tool error KS_DENIED: session state is unavailable`. The messages of the gateway are a short
    fixed set, so the kinds stay few; a message that varies is cut at 60 characters."""
    code = _code(result) or ""
    text = ""
    for block in result.content:
        text = str(getattr(block, "text", "") or "")
        if text:
            break
    found = TAG.match(text)
    message = CALL_ID.sub("", (found.group(2) if found else text)).strip().replace("\n", " ")[:60]
    kind = f"tool error {code}" if code else "tool error"
    return f"{kind}: {message}" if message else kind


def payload(size: int) -> str:
    """`size` bytes of the paragraph, repeated and cut. It is ASCII, so a character is a byte."""
    if size < 1:
        raise ValueError("the payload must have at least one byte")
    return (PARAGRAPH * (size // len(PARAGRAPH) + 1))[:size]


@dataclass(frozen=True)
class Spec:
    """What one run does. `headers` hold the credentials of the target."""

    url: str
    tool: str
    headers: Mapping[str, str]
    sessions: int
    calls: int
    size: int
    warmup: int = 3
    # A user of the local realm to act as, with a token of its own for each process.
    user: str | None = None
    client: str = "ops-agent"
    # A run that has lasted this long stops making calls, and says so. A gateway that answers ten
    # calls a second would take most of an hour over the full matrix.
    max_s: float = MAX_RUN_S

    def share(self, sessions: int) -> Spec:
        return replace(self, sessions=sessions)


@dataclass
class Collected:
    """What a process measured."""

    # The calls that succeeded, and the ones that failed, apart: see `summarize`.
    latencies_ms: list[float] = field(default_factory=list)
    failed_ms: list[float] = field(default_factory=list)
    errors: Counter[str] = field(default_factory=Counter)
    opened: int = 0
    wall_s: float = 0.0
    cpu_s: float = 0.0
    stopped_early: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "latencies_ms": self.latencies_ms,
            "failed_ms": self.failed_ms,
            "errors": dict(self.errors),
            "opened": self.opened,
            "wall_s": self.wall_s,
            "cpu_s": self.cpu_s,
            "stopped_early": self.stopped_early,
        }


async def one_session(
    spec: Spec,
    text: str,
    bearer: Bearer | None,
    collected: Collected,
    opened: Callable[[], None],
    started: anyio.Event,
) -> None:
    """Open a session, make its calls that are not counted, wait for the others, then make the
    calls that are."""
    arguments = {"payload": text}
    async with AsyncExitStack() as stack:
        try:
            # No timeout wraps the opening: the client starts tasks of its own, and a scope must be
            # left in the order it was entered. The run is bounded by the wait in `run_worker`.
            http = httpx2.AsyncClient(
                headers=dict(spec.headers), auth=bearer, timeout=httpx2.Timeout(CALL_TIMEOUT_S)
            )
            await stack.enter_async_context(http)
            transport = streamable_http_client(spec.url, http_client=http)
            client = await stack.enter_async_context(Client(transport))
            for _ in range(spec.warmup):
                with anyio.fail_after(CALL_TIMEOUT_S):
                    await client.call_tool(spec.tool, arguments)
        except Exception as error:
            collected.errors[f"open: {type(error).__name__}"] += 1
            opened()  # the others are not kept waiting for a session that will not come
            return
        collected.opened += 1
        opened()
        await started.wait()
        stop_at = time.perf_counter() + spec.max_s
        for _ in range(spec.calls):
            if time.perf_counter() >= stop_at:
                collected.stopped_early = True
                break
            began = time.perf_counter_ns()
            failed: str | None = None
            try:
                with anyio.fail_after(CALL_TIMEOUT_S):
                    result = await client.call_tool(spec.tool, arguments)
                if result.is_error:
                    failed = error_kind(result)
            except Exception as error:
                failed = type(error).__name__
            took = round((time.perf_counter_ns() - began) / 1e6, 3)
            if failed:
                collected.errors[failed] += 1
                collected.failed_ms.append(took)
            else:
                collected.latencies_ms.append(took)


async def run_worker(
    spec: Spec,
    on_ready: Callable[[], None] | None = None,
    go: Callable[[], Awaitable[None]] | None = None,
) -> Collected:
    """Run the sessions of one process. `on_ready` is called when every session is open and
    warm, and the calls start when `go` returns (at once, if there is none)."""
    collected = Collected()
    text = payload(spec.size)
    started = anyio.Event()
    all_open = anyio.Event()
    pending = spec.sessions
    bearer = None
    if spec.user is not None:
        bearer = Bearer(await anyio.to_thread.run_sync(fetch_token, spec.user, spec.client))

    def opened() -> None:
        nonlocal pending
        pending -= 1
        if pending == 0:
            all_open.set()

    async with anyio.create_task_group() as refresher:
        if bearer is not None and spec.user is not None:
            refresher.start_soon(keep_fresh, bearer, spec.user, spec.client)
        async with anyio.create_task_group() as tasks:
            for _ in range(spec.sessions):
                tasks.start_soon(one_session, spec, text, bearer, collected, opened, started)
            with anyio.fail_after(SETUP_TIMEOUT_S):
                await all_open.wait()
            if on_ready is not None:
                on_ready()
            if go is not None:
                await go()
            began, cpu = time.perf_counter(), time.process_time()
            started.set()
        collected.wall_s = time.perf_counter() - began
        collected.cpu_s = time.process_time() - cpu
        refresher.cancel_scope.cancel()
    return collected


async def read_line(stream: asyncio.StreamReader, timeout_s: float) -> str:
    line = await asyncio.wait_for(stream.readline(), timeout_s)
    if not line:
        raise RuntimeError("a load process ended without answering")
    return line.decode().strip()


def pipes(child: asyncio.subprocess.Process) -> tuple[asyncio.StreamWriter, asyncio.StreamReader]:
    if child.stdin is None or child.stdout is None:
        raise RuntimeError("a load process was started without its pipes")
    return child.stdin, child.stdout


async def run_children(
    spec: Spec, shares: list[int], on_go: Callable[[], Awaitable[None]] | None = None
) -> list[Collected]:
    """Start a process for each share of the sessions, wait until every one has its sessions open,
    say go to all of them at once, and collect what they measured."""
    children = [
        await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "eval.perf.load",
            "--worker",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        for _ in shares
    ]
    try:
        for child, share in zip(children, shares, strict=True):
            writer, _ = pipes(child)
            writer.write((json.dumps(asdict(spec.share(share))) + "\n").encode())
            await writer.drain()
        for child in children:
            if await read_line(pipes(child)[1], SETUP_TIMEOUT_S + 60) != READY:
                raise RuntimeError("a load process did not say it was ready")
        if on_go is not None:
            await on_go()
        for child in children:
            writer, _ = pipes(child)
            writer.write(f"{GO}\n".encode())
            await writer.drain()
        answers = [
            json.loads(await read_line(pipes(child)[1], spec.max_s + CALL_TIMEOUT_S + 60))
            for child in children
        ]
        for child in children:
            await child.wait()
    finally:
        for child in children:
            if child.returncode is None:
                child.kill()
    return [
        Collected(
            latencies_ms=answer["latencies_ms"],
            failed_ms=answer["failed_ms"],
            errors=Counter(answer["errors"]),
            opened=answer["opened"],
            wall_s=answer["wall_s"],
            cpu_s=answer["cpu_s"],
            stopped_early=answer["stopped_early"],
        )
        for answer in answers
    ]


async def run_load(
    spec: Spec, processes: int = 4, on_go: Callable[[], Awaitable[None]] | None = None
) -> dict[str, Any]:
    """Run a load and say what it measured: the summary of the latencies, the errors by kind, the
    sessions that opened, and how busy each process of the generator was. With one process the
    sessions run in this one. `on_go` is awaited when every session is open and warm, just before
    the calls that are timed begin: the place to read a counter to compare with another read
    after the run."""
    processes = max(1, min(processes, spec.sessions))
    if processes == 1:
        parts = [await run_worker(spec, go=on_go)]
    else:
        shares = [
            spec.sessions // processes + (1 if i < spec.sessions % processes else 0)
            for i in range(processes)
        ]
        parts = await run_children(spec, shares, on_go)
    latencies = [value for part in parts for value in part.latencies_ms]
    failed = [value for part in parts for value in part.failed_ms]
    errors: Counter[str] = Counter()
    for part in parts:
        errors.update(part.errors)
    failed_calls = sum(n for kind, n in errors.items() if not kind.startswith("open: "))
    wall = max(part.wall_s for part in parts)
    return {
        "spec": {
            "url": spec.url,
            "tool": spec.tool,
            "sessions": spec.sessions,
            "calls": spec.calls,
            "size": spec.size,
            "warmup": spec.warmup,
            "max_s": spec.max_s,
            "processes": processes,
        },
        "summary": summarize(latencies, wall, failed_calls) if latencies or failed_calls else None,
        "errors": dict(errors),
        "opened": sum(part.opened for part in parts),
        "stopped_early": any(part.stopped_early for part in parts),
        "generator": [{"wall_s": p.wall_s, "cpu_s": p.cpu_s} for p in parts],
        "latencies_ms": latencies,
        "failed_ms": failed,
    }


async def worker_main() -> int:
    """The other end of `run_load`: the spec on the first line of stdin, `ready` when every
    session is open, the calls when `go` arrives, and the result as one line of JSON."""
    # What a library prints must not be taken for an answer, so the answers go to the real standard
    # output and anything else to the error output.
    answers, sys.stdout = sys.stdout, sys.stderr
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    spec = Spec(**json.loads((await reader.readline()).decode()))

    def say_ready() -> None:
        answers.write(READY + "\n")
        answers.flush()

    async def wait_for_go() -> None:
        if (await reader.readline()).decode().strip() != GO:
            raise RuntimeError("the parent did not say go")

    collected = await run_worker(spec, say_ready, wait_for_go)
    answers.write(json.dumps(collected.as_dict()) + "\n")
    answers.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Load an MCP endpoint and time every call")
    parser.add_argument("--worker", action="store_true", help="the child process (internal)")
    parser.add_argument("--url", help="the MCP endpoint")
    parser.add_argument("--tool", default="echo__echo")
    parser.add_argument("--header", action="append", default=[], help="NAME=VALUE, repeatable")
    parser.add_argument("--user", help="get a token for this user of the local realm")
    parser.add_argument("--client", default="ops-agent", help="the OAuth client for --user")
    parser.add_argument("--sessions", type=int, default=200)
    parser.add_argument("--calls", type=int, default=20)
    parser.add_argument("--size", type=int, default=1024, help="bytes of payload")
    parser.add_argument("--processes", type=int, default=4)
    parser.add_argument("--out", type=Path, help="write the run as JSON")
    args = parser.parse_args(argv)

    if args.worker:
        return asyncio.run(worker_main())
    if not args.url:
        parser.error("--url is required")
    headers = dict(item.split("=", 1) for item in args.header)
    spec = Spec(
        args.url,
        args.tool,
        headers,
        args.sessions,
        args.calls,
        args.size,
        user=args.user,
        client=args.client,
    )
    result = asyncio.run(run_load(spec, args.processes))
    summary = result["summary"]
    print(json.dumps({k: v for k, v in result.items() if k != "latencies_ms"}, indent=2))
    if args.out:
        args.out.write_text(json.dumps(result), encoding="utf-8")
    return 0 if summary and summary["errors"] == 0 and result["opened"] == args.sessions else 1


if __name__ == "__main__":
    sys.exit(main())
