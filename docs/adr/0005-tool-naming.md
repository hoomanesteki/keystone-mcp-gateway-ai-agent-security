# ADR-0005: Exposed tool names are `<upstream>__<tool>`

Status: accepted
Date: 2026-10-21

## Context

Two upstreams can both define a tool called `search`, so the gateway must namespace what it
exposes. The MCP spec allows letters, digits, `_`, `-` and `.` in a tool name, up to 128
characters. The Anthropic and OpenAI tool-calling APIs accept letters, digits, `_` and `-`, up
to 64. A dot, a colon or a slash would pass the MCP SDK and then fail inside the model API.

## Decision

The exposed name is `<upstream_id>__<tool_name>`, for example `mail__read_email`.

- It must match `^[a-zA-Z0-9_-]{1,64}$`. `make_tool_name` raises `ValueError` otherwise.
- An upstream id matches `^[a-z][a-z0-9_]{1,30}$` and never contains `__`, so splitting on the
  first `__` is unambiguous. The tool part may contain `__`.
- A tool whose name would exceed 64 characters is rejected at registration, not truncated.
  Truncation could make two tools collide.

## Consequences

- Any client that can call a model API can call Keystone's tools without renaming.
- Upstream tool names with a dot cannot be exposed as they are. Registration fails loudly. There
  is no renaming map yet.
- Policies and audit records use the exposed name. The upstream tool name is stored beside it.

## Revisit when

Never for the separator. The length limit follows the model APIs, so revisit it if they change.
