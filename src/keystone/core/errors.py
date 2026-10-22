"""Rejection codes and the way a rejection reaches the agent (ADR-0007)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from keystone.core.types import ToolResult


class Code(StrEnum):
    DENIED = "KS_DENIED"
    APPROVAL_PENDING = "KS_APPROVAL_PENDING"
    APPROVAL_REJECTED = "KS_APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "KS_APPROVAL_EXPIRED"
    QUARANTINED = "KS_QUARANTINED"
    RATE_LIMITED = "KS_RATE_LIMITED"
    BUDGET_EXCEEDED = "KS_BUDGET_EXCEEDED"
    TOOL_NOT_FOUND = "KS_TOOL_NOT_FOUND"
    UPSTREAM_ERROR = "KS_UPSTREAM_ERROR"
    UPSTREAM_TIMEOUT = "KS_UPSTREAM_TIMEOUT"
    OUTPUT_BLOCKED = "KS_OUTPUT_BLOCKED"
    INVALID_ARGUMENTS = "KS_INVALID_ARGUMENTS"


class Reject(Exception):
    def __init__(self, code: Code, message: str, data: dict[str, Any] | None = None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data or {}


# The sentence between the call id and the message. KS_DENIED reads "denied", as in the contract.
_VERB: dict[Code, str] = {
    Code.DENIED: "denied",
    Code.APPROVAL_PENDING: "is waiting for approval",
    Code.APPROVAL_REJECTED: "was rejected by an approver",
    Code.APPROVAL_EXPIRED: "approval expired",
    Code.QUARANTINED: "blocked",
    Code.RATE_LIMITED: "rate limited",
    Code.BUDGET_EXCEEDED: "over budget",
    Code.TOOL_NOT_FOUND: "failed",
    Code.UPSTREAM_ERROR: "failed",
    Code.UPSTREAM_TIMEOUT: "timed out",
    Code.OUTPUT_BLOCKED: "output blocked",
    Code.INVALID_ARGUMENTS: "rejected",
}


def to_tool_result(r: Reject, call_id: str) -> ToolResult:
    """Rejections go back to the agent as a tool result with is_error=True,
    so the model can read the reason and adapt (ADR-0007). Text format:
    [keystone:KS_DENIED] call 01J... denied: <message>
    Machine-readable copy goes in _meta: {"keystone/code", "keystone/call_id", ...data}.

    ToolResult has no result-level meta field, and its contract does not change here, so the
    _meta rides on the text content block, which MCP allows.
    """
    text = f"[keystone:{r.code.value}] call {call_id} {_VERB[r.code]}: {r.message}"
    # The code and call id are written last, so Reject.data cannot overwrite them.
    meta = {**r.data, "keystone/code": r.code.value, "keystone/call_id": call_id}
    return ToolResult(content=[{"type": "text", "text": text, "_meta": meta}], is_error=True)
