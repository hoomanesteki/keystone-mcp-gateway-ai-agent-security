"""The shapes of the admin API's answers (KS-507). The OpenAPI schema describes these."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Effect = Literal["allow", "deny", "require_approval"]
Outcome = Literal["ok", "rejected", "error"]
ToolState = Literal["active", "quarantined", "disabled"]


class AuditRecord(BaseModel):
    """One record of the audit log, in the form its hash covers: timestamps and decimals are
    strings. The same record is a line of `keystone audit export`."""

    seq: int
    ts: str
    call_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    session_id: str
    tool_name: str
    effect: Effect | None
    decision_source: str | None
    reasons: list[str]
    policy_version: str | None
    outcome: Outcome
    reject_code: str | None
    dispatched: bool
    args_redacted: Any
    args_digest: str | None
    scan_score: str | None
    scan_action: str | None
    cost_usd: str
    latency_ms: str | None
    trace_id: str | None
    prev_hash: str
    hash: str


class AuditPage(BaseModel):
    items: list[AuditRecord]
    next_cursor: int | None = Field(
        default=None,
        description="Pass as `cursor` to get the next page. Null on the last page.",
    )


class VerifyResult(BaseModel):
    """The check of the hash chain. The chain runs through every tenant's records, so this is
    about the whole log, and it says nothing of any tenant's data."""

    ok: bool
    records: int = Field(description="How many records were good before the first problem.")
    broken_seq: int | None = None
    problem: Literal["hash mismatch", "gap"] | None = None
    message: str


class ToolSummary(BaseModel):
    name: str
    upstream: str
    status: ToolState
    risk: str
    tags: list[str]
    reason: str | None = Field(description="Why the tool is not active, if it is not.")
    pending: bool = Field(description="A changed definition waits for a person.")
    description_hash: str
    schema_hash: str


class ToolDiff(BaseModel):
    description: str
    input_schema: str


class ToolDetail(ToolSummary):
    description: str
    input_schema: dict[str, Any]
    description_screening: list[str]
    pending_description: str | None
    pending_schema: dict[str, Any] | None
    pending_screening: list[str]
    fingerprint: str | None = Field(
        description="Of the pending definition. Send it as `expect` to approve exactly that one."
    )
    diff: ToolDiff | None


class ApproveChange(BaseModel):
    note: str | None = Field(default=None, max_length=500, description="Why. Goes in the log.")
    expect: str | None = Field(
        default=None,
        min_length=6,
        max_length=64,
        pattern="^[0-9a-fA-F]+$",
        description="The fingerprint from the tool's detail (a prefix will do). The approval is "
        "refused if the pending definition no longer has it.",
    )


class UpstreamInfo(BaseModel):
    id: str
    transport: str
    status: str
    source: str
    credential_mode: str
    target: str = Field(
        description="The URL without credentials, or the program of a stdio server."
    )
    last_sync_at: str | None
    last_error: str | None


class SessionInfo(BaseModel):
    session_id: str
    user_id: str
    agent_id: str
    created_at: str
    flags: list[str]
    tainted: bool
    call_count: int
    spent_usd: float


class PolicyEntry(BaseModel):
    id: str
    effect: Literal["permit", "forbid"]
    kind: str
    file: str


class PolicySummary(BaseModel):
    version: str
    policies: list[PolicyEntry]


class ErrorBody(BaseModel):
    error: str
    reason: str
