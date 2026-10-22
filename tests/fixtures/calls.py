"""Builders for a CallContext, so pipeline tests do not repeat the same 30 lines."""

from datetime import UTC, datetime
from typing import Any

from keystone.core.ids import new_id
from keystone.core.types import CallContext, Principal, SessionState, ToolRef

ECHO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"text": {"type": "string"}},
    "required": ["text"],
    "additionalProperties": False,
}

OLIVIA = Principal(tenant_id="acme", user_id="olivia", groups=("operators",), agent_id="ops-agent")


def make_tool(
    upstream_id: str = "echo",
    tool: str = "echo",
    schema: dict[str, Any] | None = None,
    **fields: Any,
) -> ToolRef:
    return ToolRef(
        name=f"{upstream_id}__{tool}",
        upstream_id=upstream_id,
        upstream_tool_name=tool,
        tenant_id=OLIVIA.tenant_id,
        description=f"{tool} on {upstream_id}",
        input_schema=ECHO_SCHEMA if schema is None else schema,
        description_hash="d",
        schema_hash="s",
        **fields,
    )


def make_ctx(
    arguments: dict[str, Any] | None = None, tool: ToolRef | None = None, **fields: Any
) -> CallContext:
    now = datetime.now(UTC)
    return CallContext(
        call_id=new_id(),
        received_at=now,
        principal=OLIVIA,
        session=SessionState(session_id="session-1", principal=OLIVIA, created_at=now),
        tool=tool or make_tool(),
        arguments={"text": "hello"} if arguments is None else arguments,
        **fields,
    )
