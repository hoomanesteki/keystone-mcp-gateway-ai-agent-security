# ADR-0003: Python with the MCP low-level server

Status: accepted
Date: 2026-10-21

## Context

Keystone sits between an agent and its MCP servers. Every tool call crosses it, so the choice
of language and SDK sets both the build speed and the per-call overhead. A Go gateway would
likely add less overhead. I know Python better, the policy, scanner and eval work in later phases
is Python, and the MCP Python SDK is the reference implementation. I have not measured the
overhead of either option. Phase 9 measures it.

The SDK I installed is `mcp` 2.3.0, a new major version. It differs from the v1 API in ways that
matter for a proxy. The spike (`docs/spikes/mcp-proxy.md`) lists every difference. Two matter
most here:

- The server speaks two protocol eras. The handshake era has sessions (`Mcp-Session-Id`). The
  `2026-07-28` era has none.
- The default client probes for the newer era first, so a gateway that does nothing speaks it.

## Decision

- Python 3.12 and `mcp` 2.3.0. The version is pinned in `uv.lock` and listed in ADR-0002.
- The gateway is the low-level `mcp.server.Server` with `on_list_tools` and `on_call_tool`
  handlers. It is served by one `StreamableHTTPSessionManager` per app, started in the FastAPI
  lifespan, and routed with a Starlette `Route` at `/mcp`. The high-level `MCPServer` is for
  the demo upstreams only, because it owns the tool list and the gateway must not.
- The gateway serves the handshake era only. A server middleware answers the newer era with
  `UNSUPPORTED_PROTOCOL_VERSION` and the handshake versions, and a client in `auto` mode then
  falls back to `initialize` by itself. Session state (flags, taint, spend) is keyed by session
  id, and the newer era has none.
- Upstream clients are `mcp.Client` in `auto` mode, one per credential set. Each one is entered
  and left inside a single background task (engineering note 1).
- Handlers read the caller from `ctx.request`, the Starlette request, and cast it once.

## Consequences

- The gateway code depends on SDK names that are new and partly provisional. `Server.middleware`
  is marked provisional in the SDK source. `tests/integration/test_spike_proxy.py` pins the
  behavior, so an upgrade that moves it fails there.
- A client that pins the `2026-07-28` version cannot connect. Clients in `auto` mode, in
  `legacy` mode, and clients built on the v1 SDK all work.
- The SDK pulls in `httpx2` and `mcp-types`. ADR-0002 lists them.

## Revisit when

Profiling shows p95 gateway overhead above the target in the plan, or a client I need to
support can only speak the `2026-07-28` era. In that case a new ADR defines what a session
means without a session id.
