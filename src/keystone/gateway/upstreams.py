"""Clients for upstream MCP servers, and the pool that keeps them open (ADR-0003).

Each HttpUpstreamClient holds its MCP session open inside one background task, from the moment
it connects until it is closed. The anyio cancel scopes in the SDK's transport must be left in the
task that entered them (engineering note 1), so request handlers never enter or leave a session.
They borrow the open one.

A call is only resent when the upstream refused it before running the tool (its session was
gone). A call that died in flight is not resent, because the tool may already have run and a
second transfer or email would be a second effect.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from types import TracebackType
from typing import Any, Literal, Protocol, Self

import anyio
import httpx2
import structlog
from anyio.abc import TaskGroup
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from pydantic import BaseModel, SecretStr

from keystone.core.canonical import canonical_json
from keystone.core.errors import Code, Reject
from keystone.core.types import ToolResult

log = structlog.get_logger()

# Waits between a failed connection attempt and the next one: three retries, then give up.
RECONNECT_BACKOFF_S = (0.2, 0.8, 3.2)
CONNECT_TIMEOUT_S = 10.0
LIST_TIMEOUT_S = 10.0
HEALTH_TIMEOUT_S = 2.0
CLOSE_TIMEOUT_S = 5.0
MAX_LIST_PAGES = 100
MAX_POOL_CLIENTS = 100

# What a server says when it no longer knows our session id (an upstream restart).
_SESSION_LOST = {"Session not found", "Session terminated"}
_INVALID_REQUEST = -32600

Protocol_ = Literal["auto", "legacy"]


class UpstreamTool(BaseModel, frozen=True):
    name: str
    description: str
    input_schema: dict[str, Any]


class UpstreamClient(Protocol):
    async def list_tools(self) -> list[UpstreamTool]: ...
    async def call_tool(self, name: str, args: dict[str, Any], timeout_s: float) -> ToolResult: ...
    async def health(self) -> bool: ...
    async def aclose(self) -> None: ...


def inject_trace_headers(headers: dict[str, str]) -> None:
    """A no-op until KS-504 adds trace propagation. Headers are fixed per session."""


def _session_lost(exc: MCPError) -> bool:
    return exc.error.code == _INVALID_REQUEST and exc.error.message in _SESSION_LOST


class _Connection:
    """One MCP session, owned by one task from open to close."""

    def __init__(self, upstream_id: str, url: str, headers: Mapping[str, str], protocol: str):
        self.upstream_id = upstream_id
        self.url = url
        self.headers = dict(headers)
        self.protocol = protocol
        self.client: Client | None = None
        self.ready = anyio.Event()
        self.closing = anyio.Event()
        self.done = anyio.Event()
        # Lets another task abandon a connection that hangs before it is ready.
        self.scope = anyio.CancelScope()

    @property
    def usable(self) -> bool:
        return self.client is not None and not self.done.is_set()

    async def run(self) -> None:
        try:
            with self.scope:
                async with httpx2.AsyncClient(
                    headers=self.headers,
                    timeout=httpx2.Timeout(CONNECT_TIMEOUT_S, read=300.0),
                    follow_redirects=False,
                ) as http:
                    transport = streamable_http_client(self.url, http_client=http)
                    mode: Any = self.protocol
                    async with Client(transport, mode=mode) as client:
                        self.client = client
                        self.ready.set()
                        await self.closing.wait()
        except Exception as exc:
            # The text of the error can hold the URL and header values, so log its type only.
            log.warning(
                "upstream_connection_ended", upstream=self.upstream_id, error=type(exc).__name__
            )
        finally:
            self.client = None
            self.done.set()
            self.ready.set()

    async def close(self) -> None:
        self.closing.set()
        with anyio.move_on_after(CLOSE_TIMEOUT_S, shield=True) as limit:
            await self.done.wait()
        if limit.cancelled_caught:
            self.scope.cancel()
            with anyio.move_on_after(CLOSE_TIMEOUT_S, shield=True):
                await self.done.wait()


class HttpUpstreamClient:
    def __init__(
        self,
        url: str,
        headers: Mapping[str, str] | None,
        task_group: TaskGroup,
        *,
        upstream_id: str = "upstream",
        protocol: Protocol_ = "auto",
        backoff_s: Sequence[float] = RECONNECT_BACKOFF_S,
    ) -> None:
        self.url = url
        self.upstream_id = upstream_id
        self._headers = dict(headers or {})
        inject_trace_headers(self._headers)
        self._task_group = task_group
        self._protocol = protocol
        self._backoff_s = tuple(backoff_s)
        self._connection: _Connection | None = None
        self._lock = anyio.Lock()
        self._closed = False

    async def list_tools(self) -> list[UpstreamTool]:
        try:
            with anyio.fail_after(LIST_TIMEOUT_S):
                return await self._with_session(self._list_all)
        except TimeoutError:
            raise Reject(
                Code.UPSTREAM_TIMEOUT, "the upstream server did not list its tools"
            ) from None

    async def call_tool(self, name: str, args: dict[str, Any], timeout_s: float) -> ToolResult:
        async def call(client: Client) -> ToolResult:
            return convert_result(await client.call_tool(name, args))

        try:
            with anyio.fail_after(timeout_s):
                return await self._with_session(call)
        except TimeoutError:
            raise Reject(
                Code.UPSTREAM_TIMEOUT, f"the upstream server did not answer within {timeout_s:g} s"
            ) from None

    async def health(self) -> bool:
        connection = self._connection
        if self._closed or connection is None or connection.client is None:
            return False
        try:
            with anyio.fail_after(HEALTH_TIMEOUT_S):
                # ping is gone in the newer protocol era, so ask for the first page of tools.
                await connection.client.list_tools(cache_mode="refresh")
        except Exception:
            return False
        return True

    async def aclose(self) -> None:
        self._closed = True
        connection, self._connection = self._connection, None
        if connection is not None:
            await connection.close()

    async def _list_all(self, client: Client) -> list[UpstreamTool]:
        tools: list[UpstreamTool] = []
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            page = await client.list_tools(cursor=cursor, cache_mode="refresh")
            tools += [
                UpstreamTool(
                    name=t.name, description=t.description or "", input_schema=dict(t.input_schema)
                )
                for t in page.tools
            ]
            cursor = page.next_cursor
            if cursor is None:
                return tools
        # A partial list would look like a list in which the rest of the tools had vanished, and
        # the registry would disable them.
        raise Reject(
            Code.UPSTREAM_ERROR, "the upstream server lists more tools than Keystone reads"
        )

    async def _with_session[T](self, action: Callable[[Client], Awaitable[T]]) -> T:
        for attempt in range(2):
            client = await self._client()
            try:
                return await action(client)
            except Reject:
                raise
            except MCPError as exc:
                if _session_lost(exc) and attempt == 0:
                    # The server refused the request before running anything, so sending it
                    # again on a fresh session cannot repeat an effect.
                    log.info("upstream_session_lost", upstream=self.upstream_id)
                    await self._drop(client)
                    continue
                await self._drop_if_dead(client, exc)
                log.warning(
                    "upstream_protocol_error", upstream=self.upstream_id, code=exc.error.code
                )
                raise Reject(Code.UPSTREAM_ERROR, _MCP_ERROR_MESSAGE) from None
            except Exception as exc:
                await self._drop(client)
                log.warning(
                    "upstream_call_failed", upstream=self.upstream_id, error=type(exc).__name__
                )
                raise Reject(
                    Code.UPSTREAM_ERROR, "the upstream server dropped the connection"
                ) from None
        raise Reject(Code.UPSTREAM_ERROR, "the upstream server lost the session twice")

    async def _client(self) -> Client:
        async with self._lock:
            if self._closed:
                raise Reject(Code.UPSTREAM_ERROR, "the connection to the upstream server is closed")
            connection = self._connection
            if connection is not None and connection.client is not None and connection.usable:
                return connection.client
            if connection is not None:
                self._connection = None
                await connection.close()
            for attempt in range(len(self._backoff_s) + 1):
                if attempt:
                    await anyio.sleep(self._backoff_s[attempt - 1])
                opened = await self._open()
                if opened.client is not None:
                    self._connection = opened
                    return opened.client
            raise Reject(Code.UPSTREAM_ERROR, "the upstream server is not reachable")

    async def _open(self) -> _Connection:
        connection = _Connection(self.upstream_id, self.url, self._headers, self._protocol)
        self._task_group.start_soon(connection.run)
        try:
            with anyio.fail_after(CONNECT_TIMEOUT_S):
                await connection.ready.wait()
        except BaseException:
            # A timeout or a cancelled caller must not leave a half-open session behind.
            connection.scope.cancel()
            raise
        return connection

    async def _drop(self, client: Client) -> None:
        """Close the session if it is still the current one, so the next call reconnects."""
        async with self._lock:
            connection = self._connection
            if connection is not None and connection.client is client:
                self._connection = None
                await connection.close()

    async def _drop_if_dead(self, client: Client, exc: MCPError) -> None:
        if exc.error.message == "Connection closed":
            await self._drop(client)


_MCP_ERROR_MESSAGE = "the upstream server rejected the request"
_DROPPED_MESSAGE = "the upstream server dropped the connection"


def convert_result(result: Any) -> ToolResult:
    """An SDK CallToolResult as a ToolResult. The upstream's own _meta is left behind: in the
    newer protocol era it names the upstream server, and this is not that server's answer."""
    structured = result.structured_content
    return ToolResult(
        content=[
            block.model_dump(by_alias=True, mode="json", exclude_none=True)
            for block in result.content
        ],
        # The contract allows an object only. Content still carries a list or a scalar.
        structured_content=structured if isinstance(structured, dict) else None,
        is_error=result.is_error,
    )


ClientFactory = Callable[[str, dict[str, str], TaskGroup], UpstreamClient]


def headers_fingerprint(headers: Mapping[str, SecretStr]) -> str:
    """A digest of the header names and values. It is a pool key, never logged or stored."""
    pairs = sorted((name.lower(), value.get_secret_value()) for name, value in headers.items())
    return hashlib.sha256(canonical_json(pairs)).hexdigest()


class _Entry:
    """A pooled client and the number of calls running on it."""

    __slots__ = ("client", "closed", "evicted", "in_flight")

    def __init__(self, client: UpstreamClient) -> None:
        self.client = client
        self.in_flight = 0
        self.evicted = False
        self.closed = False


class UpstreamPool:
    """Clients keyed by (upstream id, header fingerprint), least recently used out first.

    Use it as `async with UpstreamPool(factory) as pool` in the one task that lives as long as
    the app (the lifespan). Its task group owns the sessions' background tasks.

    A caller that makes a call takes the client with `lease`, which counts the call as in flight.
    An evicted client leaves the pool at once, so no new call can get it, but it is closed only
    after its last in-flight call has finished (KS-192). Closing the pool closes every client,
    leased or not, because the app is going away.
    """

    def __init__(self, factory: ClientFactory, max_clients: int = MAX_POOL_CLIENTS) -> None:
        self._factory = factory
        self._max = max_clients
        self._clients: OrderedDict[tuple[str, str], _Entry] = OrderedDict()
        self._draining: set[_Entry] = set()  # evicted, with calls still running
        self._stack: AsyncExitStack | None = None
        self._task_group: TaskGroup | None = None

    async def __aenter__(self) -> Self:
        async with AsyncExitStack() as stack:
            self._task_group = await stack.enter_async_context(anyio.create_task_group())
            self._stack = stack.pop_all()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        entries = [*self._clients.values(), *self._draining]
        self._clients, self._draining = OrderedDict(), set()
        with anyio.CancelScope(shield=True):
            for entry in entries:
                await self._close(entry)
        stack, self._stack, self._task_group = self._stack, None, None
        if stack is not None:
            await stack.__aexit__(exc_type, exc, tb)

    async def get(
        self, upstream_id: str, headers: Mapping[str, SecretStr] | None = None
    ) -> UpstreamClient:
        """The client for one upstream and one set of headers. For a call, use `lease`: a client
        taken with `get` can be closed by an eviction while it is in use."""
        entry, evicted = self._checkout(upstream_id, headers)
        await self._retire(evicted)
        return entry.client

    @asynccontextmanager
    async def lease(
        self, upstream_id: str, headers: Mapping[str, SecretStr] | None = None
    ) -> AsyncIterator[UpstreamClient]:
        entry, evicted = self._checkout(upstream_id, headers)
        # No await between the checkout and the count, so an eviction cannot slip in between.
        entry.in_flight += 1
        try:
            await self._retire(evicted)
            yield entry.client
        finally:
            await self._release(entry)

    def _checkout(
        self, upstream_id: str, headers: Mapping[str, SecretStr] | None
    ) -> tuple[_Entry, list[_Entry]]:
        """Find or build the client and name the ones this pushes out. It never awaits, so the
        pool's bookkeeping cannot interleave with another caller's."""
        if self._task_group is None:
            raise RuntimeError("the upstream pool is not running")
        secrets = headers or {}
        key = (upstream_id, headers_fingerprint(secrets))
        entry = self._clients.get(key)
        if entry is not None:
            self._clients.move_to_end(key)
            return entry, []
        plain = {name: value.get_secret_value() for name, value in secrets.items()}
        entry = _Entry(self._factory(upstream_id, plain, self._task_group))
        self._clients[key] = entry
        evicted = [
            self._clients.popitem(last=False)[1] for _ in range(len(self._clients) - self._max)
        ]
        for old in evicted:
            old.evicted = True
        return entry, evicted

    async def forget(self, upstream_id: str) -> None:
        """Drop every client of one upstream, for example after its URL changed. Calls already
        running finish on the old client, which closes after the last of them."""
        keys = [key for key in self._clients if key[0] == upstream_id]
        entries = [self._clients.pop(key) for key in keys]
        for entry in entries:
            entry.evicted = True
        await self._retire(entries)

    async def _retire(self, evicted: list[_Entry]) -> None:
        for entry in evicted:
            if entry.in_flight > 0:
                self._draining.add(entry)
            else:
                await self._close(entry)

    async def _release(self, entry: _Entry) -> None:
        # Shielded: a cancelled call must still hand the client back.
        with anyio.CancelScope(shield=True):
            entry.in_flight -= 1
            if entry.evicted and entry.in_flight == 0:
                self._draining.discard(entry)
                await self._close(entry)

    async def _close(self, entry: _Entry) -> None:
        if entry.closed:
            return
        entry.closed = True
        try:
            await entry.client.aclose()
        except Exception as exc:
            log.warning("upstream_close_failed", error=type(exc).__name__)


def http_client_factory(
    urls: Mapping[str, str],
    *,
    protocol: Protocol_ = "auto",
    backoff_s: Sequence[float] = RECONNECT_BACKOFF_S,
) -> ClientFactory:
    def make(upstream_id: str, headers: dict[str, str], task_group: TaskGroup) -> UpstreamClient:
        if upstream_id not in urls:
            raise ValueError(f"unknown upstream {upstream_id!r}")
        return HttpUpstreamClient(
            urls[upstream_id],
            headers,
            task_group,
            upstream_id=upstream_id,
            protocol=protocol,
            backoff_s=backoff_s,
        )

    return make


class UpstreamTarget(BaseModel, frozen=True):
    """Where and how to reach one upstream."""

    transport: str
    url: str | None = None
    command: tuple[str, ...] | None = None


class UpstreamDirectory:
    """Where each upstream lives. The registry keeps it current from the database, so an
    upstream added with the CLI can be reached without a restart."""

    def __init__(self) -> None:
        self._targets: dict[str, UpstreamTarget] = {}

    def get(self, upstream_id: str) -> UpstreamTarget | None:
        return self._targets.get(upstream_id)

    def update(self, targets: Mapping[str, UpstreamTarget]) -> list[str]:
        """Record the targets. Returns the ids whose target is new or different."""
        changed = [i for i, t in targets.items() if self._targets.get(i) != t]
        self._targets.update(targets)
        return changed


def directory_client_factory(
    directory: UpstreamDirectory,
    *,
    protocol: Protocol_ = "auto",
    backoff_s: Sequence[float] = RECONNECT_BACKOFF_S,
) -> ClientFactory:
    def make(upstream_id: str, headers: dict[str, str], task_group: TaskGroup) -> UpstreamClient:
        target = directory.get(upstream_id)
        if target is None:
            raise ValueError(f"unknown upstream {upstream_id!r}")
        if target.transport == "http" and target.url:
            return HttpUpstreamClient(
                target.url,
                headers,
                task_group,
                upstream_id=upstream_id,
                protocol=protocol,
                backoff_s=backoff_s,
            )
        raise ValueError(f"upstream {upstream_id!r}: transport {target.transport!r} is not served")

    return make
