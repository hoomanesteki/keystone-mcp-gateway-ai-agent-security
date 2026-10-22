# ADR-0007: Rejections return as tool results

Status: accepted
Date: 2026-10-21

## Context

When Keystone refuses a call (policy denial, pending approval, rate limit, quarantined tool,
unknown tool), the agent has to learn why. MCP has two ways to say no. A JSON-RPC error ends the
request, and many clients turn it into a failed turn with no usable text. A tool result with
`isError: true` goes back into the model's context, so the model can read the reason and ask the
user, wait for approval, or pick another tool.

## Decision

- Every pipeline rejection is a `CallToolResult` with `is_error=True` (`to_tool_result` in
  `keystone.core.errors`). This includes an unknown tool name.
- The text is `[keystone:<CODE>] call <call_id> <verb>: <message>`, for example
  `[keystone:KS_DENIED] call 01J... denied: <message>`. It is written for a model to read, and it
  never contains exception text, stack traces, secrets or upstream credentials.
- The same facts go in `_meta` for programs: `keystone/code`, `keystone/call_id`, and any `data`
  from the `Reject`. In the SDK the field is `meta` with the alias `_meta`; code passes `_meta=`.
  The plan's `ToolResult` has no result-level meta field, and its contract is unchanged, so the
  `_meta` sits on the text content block (`result.content[0].meta` in a client). MCP allows `_meta`
  on any content block.
- Missing or invalid authentication is not a tool result. It is an HTTP 401 before the MCP layer
  runs, because the client has to handle it and the model cannot fix it.
- A malformed request, an unknown method or a failed handshake stay protocol errors, because the
  SDK produces them before any tool is involved.

## Consequences

- The Phase 1 equivalence test and the later red-team scenarios check `is_error` and the code in
  `_meta`, not an exception.
- In the `2026-07-28` era the SDK adds its own key (`io.modelcontextprotocol/serverInfo`) to
  `_meta`. Keystone serves the handshake era only (ADR-0003), but any consumer must read keys by
  name and not compare the whole dict.
- A client that ignores `isError` shows the rejection text as if it were tool output. The text
  starts with the code, so it is still readable.

## Revisit when

A client I need to support mishandles error results.
