"""The shapes of the admin API's answers (KS-507). The OpenAPI schema describes these."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

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
    cost_per_call_usd: str = Field(
        description="What one call is booked at, in US dollars, as a decimal string like the "
        "audit log's cost. 0 for a tool with no price."
    )
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


ApprovalStatus = Literal["pending", "approved", "rejected", "expired", "consumed"]


class ApprovalItem(BaseModel):
    """One request for approval, as an approver needs to see it (KS-604)."""

    id: str
    status: ApprovalStatus = Field(
        description="What it is now. A request past its time is `expired` before the sweeper "
        "has marked it."
    )
    tool: str
    risk: str | None = Field(description="The tool's risk, or null if the tool is not registered.")
    tags: list[str]
    arguments: Any = Field(description="The arguments with secrets masked, as the audit log shows.")
    arguments_masked: bool = Field(
        description="Something in `arguments` was hidden or cut: a secret, a card number, a long "
        "text, or more than a row keeps. What runs is more than what is shown, so what is not "
        "shown is unknown to the person who decides."
    )
    args_digest: str = Field(description="sha256 of the arguments, the one the audit log writes.")
    reasons: list[str] = Field(
        description="The ids of the policies that sent the call to approval."
    )
    requested_by_user: str
    requested_by_agent: str
    own_request: bool = Field(
        description="The caller made this request and so cannot decide it (separation of duties)."
    )
    session_id: str
    call_id: str = Field(description="The call that asked. Its audit record has the same id.")
    requested_at: str
    expires_at: str
    expires_in_s: float = Field(
        description="Seconds until it expires, counted by the server, negative once it has."
    )
    decided_by: str | None
    decision_note: str | None
    decided_at: str | None
    flags: list[str] = Field(description="The session's flags (what it has read).")
    tainted: bool = Field(description="The session has read untrusted content.")


class ApprovalDetail(ApprovalItem):
    recent_calls: list[AuditRecord] = Field(
        description="The last 10 calls of the session that asked, newest first."
    )


class DecisionBody(BaseModel):
    # A misspelled key (`notes`) must fail and not drop the note a person wrote.
    model_config = ConfigDict(extra="forbid")

    # A JSON true or false and nothing else: "yes", "0" and 1 are not decisions.
    approve: StrictBool
    note: str | None = Field(
        default=None, max_length=500, description="Why. Rejected calls tell the agent."
    )


class ErrorBody(BaseModel):
    error: str
    reason: str
    status: str | None = Field(
        default=None, description="With a 409: what the request is now (approved, expired, ...)."
    )
