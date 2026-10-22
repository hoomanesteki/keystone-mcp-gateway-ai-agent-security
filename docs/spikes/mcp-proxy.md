# Spike: MCP SDK proxy pattern (KS-101)

I needed to know how the MCP Python SDK supports a proxy before building the gateway on it.
This page answers the five questions in the story with working code. The code is kept as
`tests/integration/test_spike_proxy.py::test_minimal_proxy_roundtrip`, so an SDK upgrade that
breaks the pattern fails there first. Every later story uses the names below.

## Versions

| Package | Version | Note |
|---|---|---|
| mcp | 2.3.0 | The latest release on 2026-10-21. A new major version: it is not the v1 API the plan assumed. |
| mcp-types | 2.3.0 | Protocol types, split out of `mcp`. `mcp.types` still re-exports them. |
| httpx2 | 2.16.0 | The SDK's HTTP client library. Not `httpx`. |
| Python | 3.12 | |

I read the installed source in `site-packages/mcp` and `site-packages/mcp_types`, then ran every
snippet. Nothing here comes from memory of the v1 API.

## What differs from the plan

| The plan assumed | mcp 2.3.0 |
|---|---|
| `FastMCP` in `mcp.server.fastmcp` | Removed. Importing it raises `ModuleNotFoundError`. The class is `mcp.server.mcpserver.MCPServer` (also `from mcp.server import MCPServer`). Tools, `custom_route` and `streamable_http_app()` work the same way. |
| Low-level `Server` with `@server.call_tool()` decorators | `mcp.server.Server(name, on_list_tools=..., on_call_tool=...)`. Handlers are `async def(ctx, params)`. The decorators are gone. |
| `server.request_context` | The first argument of every handler: `ctx: mcp.server.ServerRequestContext`. |
| Request headers through a side channel | `ctx.request` is the Starlette `Request`. It is typed `Any`, so cast it. It is `None` on stdio. |
| Types in `mcp.types` | `mcp_types` (`import mcp_types as types`). |
| `streamablehttp_client(url, headers=...)` | `streamable_http_client(url, http_client=httpx2.AsyncClient(headers=...))`. |
| `ClientSession(read, write)` then `initialize()` | `mcp.Client(url_or_transport)` owns the session and the handshake. |
| `CallToolResult(meta=...)` | The field is `meta` with the alias `_meta`. Pass `_meta=...`: mypy rejects `meta=`. |
| One protocol | Two eras on one endpoint, described next. |

### Two protocol eras

- **Handshake era** (`2024-11-05` to `2025-11-25`): `initialize`, then every request carries
  `Mcp-Session-Id`. This is the session model the plan builds on.
- **Modern era** (`2026-07-28`): no handshake and no session. Each POST is self-contained and the
  server never sets `Mcp-Session-Id`.

`mcp.Client` defaults to `mode="auto"`. It sends `server/discover` first, and if the server
answers with an error it falls back to `initialize`. Run against a plain SDK server, a default
client therefore speaks the modern era and the gateway sees no session id. `mode="legacy"`
forces the handshake. A modern version string pins the modern era.

Keystone keeps per-session state (flags, taint, call count, spend) keyed by session id
(plan sections 3.4 and 3.7). I decided to serve the handshake era only (ADR-0003). Question 2
shows how.

## 1. Low-level Server over streamable HTTP inside FastAPI

```python
server = Server("keystone", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
manager = StreamableHTTPSessionManager(app=server)  # one per app, run() works once


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    async with manager.run():
        yield


app = FastAPI(lifespan=lifespan)
app.router.routes.append(Route("/mcp", endpoint=StreamableHTTPASGIApp(manager)))
```

- `manager.run()` must be entered by the FastAPI lifespan. `Server.streamable_http_app()` builds a
  Starlette app whose own lifespan does this, but FastAPI does not run the lifespan of a mounted
  sub-app: a request to it returns 500. I tried it.
- A `Route` serves `/mcp` exactly. `app.mount("/mcp", ...)` answers `POST /mcp` with a 307 to
  `/mcp/`. The client follows it, but it costs a round trip on every request.
- A second `manager.run()` on the same instance raises `RuntimeError` (checked). Build a new manager
  and a new `Server` for each app, which is what the tests need (engineering note 2).
- `Server(lifespan=...)` is entered once by `manager.run()`, and its yielded value reaches
  handlers as `ctx.lifespan_context`. I keep the pipeline and the pool in closures instead.

## 2. Request headers and the session id in a handler

```python
async def on_call_tool(ctx: ServerRequestContext, params: types.CallToolRequestParams):
    request = cast("Request", ctx.request)  # starlette.requests.Request
    session_id = request.headers.get("mcp-session-id")
    token = request.headers.get("authorization")
```

- The plan's fallback (an ASGI middleware with a session-to-principal map) is not needed.
  `ctx.request` carries the full HTTP request in both eras.
- Handshake era: `mcp-session-id` is present on every request after `initialize`. It is also on
  the private `ctx.session._connection.session_id` (same value, checked). I read the header,
  because the private attribute can move.
- Modern era: no session id exists, so the header is absent.
- `ctx.protocol_version` says which era a request used.
- The session manager already binds a session to the credential that created it, when the
  request scope has a Starlette `AuthenticatedUser` (`scope["user"]`). A different credential
  gets 404 "Session not found". KS-304 can use this with the SDK's `BearerAuthBackend`, or do
  its own binding. I have not tried either.

To keep clients in the handshake era, a server middleware refuses the modern era with the error
that means "I only speak these versions". A client in `auto` mode then falls back by itself:

```python
async def handshake_era_only(ctx: ServerRequestContext, call_next: Any) -> Any:
    if ctx.protocol_version in MODERN_PROTOCOL_VERSIONS:
        raise MCPError(
            code=types.UNSUPPORTED_PROTOCOL_VERSION,
            message="Unsupported protocol version",
            data={
                "supported": list(HANDSHAKE_PROTOCOL_VERSIONS),
                "requested": ctx.protocol_version,
            },
        )
    return await call_next(ctx)


server.middleware.insert(0, handshake_era_only)
```

Measured with a default client: it negotiates `2025-11-25`, and every call carries the same
session id. A client pinned to `2026-07-28` gets the error and cannot connect.
`Server.middleware` is marked provisional in the SDK source (a `TODO(L54)` says the signature
may change in a 2.x minor release), so the test pins this behavior.

## 3. A per-request tool list

```python
async def on_list_tools(ctx: ServerRequestContext, params: types.PaginatedRequestParams | None):
    request = cast("Request", ctx.request)
    if request.headers.get("x-user") != "olivia":
        return types.ListToolsResult(tools=[])
    ...
```

The handler runs for every `tools/list` and sees the same context as `tools/call`, so the list
can depend on the caller. The test shows two users getting different lists. In Phase 4 the
policy engine filters here. The result defaults to `ttl_ms=0`, which tells clients not to cache
it. Do not raise that without keying the cache on the principal.

## 4. One upstream session held across many calls

Engineering note 1 holds. I tried the alternatives:

| Pattern | Result |
|---|---|
| Client entered and left inside one task, other tasks call it | Works. 20 concurrent `call_tool` calls over one open client all succeeded, and it closed cleanly. |
| Client entered in one task and left in another | Fails with `RuntimeError: Attempted to exit a cancel scope that isn't the current tasks's current cancel scope`. |

So each upstream client lives in one background task:

```python
async def hold_upstream_session(ready: anyio.Event, stop: anyio.Event) -> None:
    async with Client(upstream_url) as upstream:
        holder["upstream"] = upstream
        ready.set()
        await stop.wait()
```

For per-user credentials the headers must differ per session, and `streamable_http_client`
takes them from the HTTP client:

```python
http = httpx2.AsyncClient(headers={"X-Api-Key": key}, timeout=httpx2.Timeout(10))
client = Client(streamable_http_client(url, http_client=http))
```

A transport object can be entered once, so a reconnect builds a new `Client`. Behavior I
measured against an `MCPServer` upstream:

| Case | Modern era | Handshake era |
|---|---|---|
| `anyio.fail_after(1)` around a 5 s tool | `TimeoutError` after 1.0 s, client still usable | same |
| Upstream restarts on the same port | The next call just works | Every call raises `MCPError(-32600, 'Session not found')` until a new `Client` is made |
| Unknown tool name | `is_error=True` result with the text `Unknown tool: nope` | same |

A reconnect in KS-105 must therefore treat that `MCPError` as "open a new client", and an
upstream that speaks the modern era needs no reconnect at all.

The result of a modern-era call carries `_meta["io.modelcontextprotocol/serverInfo"]`, the
upstream's identity. A proxy that returns the upstream result object leaks it. Copy `content`,
`structured_content` and `is_error` into a new `CallToolResult`, as the spike does.

## 5. An error result with `_meta`

```python
return types.CallToolResult(
    content=[types.TextContent(text="[keystone:KS_TOOL_NOT_FOUND] other__tool")],
    is_error=True,
    _meta={"keystone/code": "KS_TOOL_NOT_FOUND"},
)
```

The client receives `is_error=True` and `meta == {"keystone/code": "KS_TOOL_NOT_FOUND"}` in the
handshake era. In the modern era the server adds the `serverInfo` key next to it, so a client
must read keys by name and not compare the whole dict. See ADR-0007.

## Other findings that later stories need

- **Demo upstreams.** `MCPServer.custom_route(path, methods)` adds plain HTTP routes
  (`/_reset`, `/_state`), and they are not tools. A tool that raises becomes an
  `is_error=True` result with the exception text. `MCPServer.run("stdio")` and
  `streamable_http_app()` cover both transports.
- **Host checks.** `Server.streamable_http_app()` turns on DNS rebinding protection
  (`Host` must be `127.0.0.1:*`, `localhost:*` or `[::1]:*`) only when it is built with a loopback
  `host`. A manager built by hand has no host check unless it is given
  `TransportSecuritySettings`. KS-106 passes explicit settings.
- **Types.** The SDK ships `py.typed`. `ctx.request` is `Any`, so every use needs a `cast`. Under
  mypy strict, annotate handlers as `ServerRequestContext[Any, Any]` (the gateway does).
- **Logging.** Constructing an `MCPServer` installs a Rich handler on the root logger at INFO
  (`configure_logging`, controlled by its `log_level` argument). That is a global side effect.
  The demo upstreams pass `log_level="WARNING"`. The low-level `Server` does not touch logging.

## What I did not test

- Resumability with an event store, and SSE streaming of progress.
- The stdio server transport of the low-level `Server` (the gateway only needs HTTP).
- The MCP Inspector browser UI. I did run the Inspector 2.12.0 command line (a TypeScript client)
  against Keystone on 2026-10-21: `tools/list` returned the 12 namespaced tools and
  `tools/call echo__echo` succeeded, with one `ok` record in the audit log. So a client that is
  not this SDK completes the handshake and reads the results.
