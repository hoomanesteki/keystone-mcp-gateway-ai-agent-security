from datetime import datetime
from decimal import Decimal
from typing import Any, cast

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    Numeric,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    """Seeded from the `tenants` list in keystone.yaml. Later tables reference it."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# The values below are checked by the database as well as by the Python types, so a bug or a
# hand-written SQL statement cannot store a state the code does not know.
TRANSPORTS = ("http", "stdio", "container_stdio", "builtin")
CREDENTIAL_MODES = ("none", "static", "per_user")
UPSTREAM_SOURCES = ("config", "cli")
UPSTREAM_STATUSES = ("unknown", "up", "degraded", "down", "disabled")
TOOL_STATUSES = ("active", "quarantined", "disabled")
RISKS = ("low", "medium", "high", "critical")
APPROVAL_STATUSES = ("pending", "approved", "rejected", "expired", "consumed")
LEDGER_KINDS = ("tool", "llm")
BUDGET_SCOPES = ("tenant", "user", "agent")
BUDGET_WINDOWS = ("day", "month")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class Upstream(Base):
    """An MCP server Keystone proxies. Rows are never deleted: audit records name upstreams and
    tools, so a removed upstream becomes `disabled` and keeps its history."""

    __tablename__ = "upstreams"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_upstreams_tenant_id_id"),
        CheckConstraint(_in("transport", TRANSPORTS), name="ck_upstreams_transport"),
        CheckConstraint(_in("credential_mode", CREDENTIAL_MODES), name="ck_upstreams_credential"),
        CheckConstraint(_in("source", UPSTREAM_SOURCES), name="ck_upstreams_source"),
        CheckConstraint(_in("status", UPSTREAM_STATUSES), name="ck_upstreams_status"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(Text, ForeignKey("tenants.id"), nullable=False)
    transport: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str | None] = mapped_column(Text)
    command: Mapped[list[str] | None] = mapped_column(JSONB(none_as_null=True))
    image: Mapped[str | None] = mapped_column(Text)
    credential_mode: Mapped[str] = mapped_column(Text, nullable=False, server_default="none")
    source: Mapped[str] = mapped_column(Text, nullable=False, server_default="config")
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="unknown")
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Tool(Base):
    """One tool of one upstream, as the registry last saw it. `pending_*` holds a changed
    definition until a person approves it (KS-205)."""

    __tablename__ = "tools"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "upstream_id"],
            ["upstreams.tenant_id", "upstreams.id"],
            name="fk_tools_upstream",
        ),
        CheckConstraint(_in("status", TOOL_STATUSES), name="ck_tools_status"),
        CheckConstraint(_in("risk", RISKS), name="ck_tools_risk"),
        Index("ix_tools_upstream", "tenant_id", "upstream_id"),
    )

    tenant_id: Mapped[str] = mapped_column(Text, ForeignKey("tenants.id"), primary_key=True)
    name: Mapped[str] = mapped_column(Text, primary_key=True)
    upstream_id: Mapped[str] = mapped_column(Text, nullable=False)
    upstream_tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    risk: Mapped[str] = mapped_column(Text, nullable=False, server_default="medium")
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'")
    )
    # No precision: a float must come back as the same float, and a fixed scale would round it.
    cost_per_call_usd: Mapped[Decimal] = mapped_column(
        Numeric, nullable=False, server_default=text("0")
    )
    timeout_s: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("30"))
    extractors: Mapped[dict[str, str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    description_hash: Mapped[str] = mapped_column(Text, nullable=False)
    schema_hash: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="active")
    pending_description: Mapped[str | None] = mapped_column(Text)
    pending_schema: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    quarantine_reason: Mapped[str | None] = mapped_column(Text)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class McpSession(Base):
    """The durable reference for an MCP session. Live state is in Redis (KS-207)."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(Text, ForeignKey("tenants.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(Text, nullable=False)
    agent_id: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    final_flags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'")
    )
    tainted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Credential(Base):
    """Headers Keystone adds to calls to one upstream, encrypted with the master key (KS-305).
    A null `user_id` is the upstream's static credential. The plaintext is never stored."""

    __tablename__ = "credentials"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "upstream_id"],
            ["upstreams.tenant_id", "upstreams.id"],
            name="fk_credentials_upstream",
        ),
        UniqueConstraint(
            "tenant_id",
            "upstream_id",
            "user_id",
            name="uq_credentials_owner",
            postgresql_nulls_not_distinct=True,
        ),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(Text, nullable=False)
    upstream_id: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[str | None] = mapped_column(Text)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # A short fingerprint of the master key that encrypted the row, never the key.
    key_id: Mapped[str] = mapped_column(Text, nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class PolicyVersion(Base):
    """A policy set that was loaded, named by the sha256 of its files. `files` keeps each file's
    path, sha256 and content, so the rules in force when a call was decided can be read back
    from the version the audit record names. The first load of a version sets `loaded_at`."""

    __tablename__ = "policy_versions"

    version: Mapped[str] = mapped_column(Text, primary_key=True)
    files: Mapped[list[dict[str, str]]] = mapped_column(JSONB, nullable=False)
    loaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuditEvent(Base):
    """One record per tool call, chained by hash (KS-501, ADR-0009). Nothing updates or deletes a
    row: the application's database role may only insert and select (KS-503).

    `ts` is the time of the call. There is no created_at, because a time the database chose would
    sit outside the hash. The writer assigns `seq` under an advisory lock, so a batch that fails
    leaves no gap, and the unique `prev_hash` refuses a second record after the same one."""

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("prev_hash", name="uq_audit_events_prev_hash"),
        CheckConstraint(
            "effect IS NULL OR effect IN ('allow', 'deny', 'require_approval')",
            name="ck_audit_events_effect",
        ),
        CheckConstraint("outcome IN ('ok', 'rejected', 'error')", name="ck_audit_events_outcome"),
        Index("ix_audit_events_tenant_seq", "tenant_id", "seq"),
        Index("ix_audit_events_tenant_ts", "tenant_id", "ts"),
        Index("ix_audit_events_call_id", "call_id"),
    )

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    call_id: Mapped[str] = mapped_column(Text, nullable=False)
    tenant_id: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[str] = mapped_column(Text, nullable=False)
    agent_id: Mapped[str] = mapped_column(Text, nullable=False)
    session_id: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    effect: Mapped[str | None] = mapped_column(Text)
    # Which part decided: policy, pinning, a rate limit.
    decision_source: Mapped[str | None] = mapped_column(Text)
    reasons: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'")
    )
    policy_version: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    reject_code: Mapped[str | None] = mapped_column(Text)
    # Whether the call reached the upstream. `outcome` cannot say: a result the output scan
    # blocked was dispatched and still rejected.
    dispatched: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    args_redacted: Mapped[Any | None] = mapped_column(JSONB(none_as_null=True))
    args_digest: Mapped[str | None] = mapped_column(Text)
    # Money, scores and durations are Decimals with a fixed scale (audit.chain.DECIMAL_SCALES), so
    # the hash of what was written equals the hash of what is read back.
    scan_score: Mapped[Decimal | None] = mapped_column(Numeric)
    scan_action: Mapped[str | None] = mapped_column(Text)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric, nullable=False, server_default=text("0"))
    latency_ms: Mapped[Decimal | None] = mapped_column(Numeric)
    trace_id: Mapped[str | None] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(Text, nullable=False)
    hash: Mapped[str] = mapped_column(Text, nullable=False)


class Approval(Base):
    """A request for a person to approve one tool call (KS-601, ADR-0010).

    The row holds what the approver needs to decide (tool, arguments with secrets masked, who asked,
    which rules asked) and what the call needs to run later: the original arguments, encrypted with
    the vault's key, and the digest of them that the approval is bound to. `expires_at` is set from
    the database clock and so is every comparison against it (see `approvals/service.py`). There is
    no foreign key to `tenants`, as in the audit log: a request outlives nothing it needs.
    """

    __tablename__ = "approvals"
    __table_args__ = (
        CheckConstraint(_in("status", APPROVAL_STATUSES), name="ck_approvals_status"),
        Index("ix_approvals_tenant_status", "tenant_id", "status"),
        Index("ix_approvals_session", "tenant_id", "session_id"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(Text, nullable=False)
    session_id: Mapped[str] = mapped_column(Text, nullable=False)
    # The call that asked. The audit record of that call carries the same id.
    call_id: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    args_redacted: Mapped[Any] = mapped_column(JSONB(none_as_null=True))
    args_digest: Mapped[str] = mapped_column(Text, nullable=False)
    args_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    reasons: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'")
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    requested_by_user: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by_agent: Mapped[str] = mapped_column(Text, nullable=False)
    decided_by: Mapped[str | None] = mapped_column(Text)
    decision_note: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class SpendLedger(Base):
    """What was spent, one row for each tool call that has a price and each model request (KS-805,
    ADR-0014). The record of money: the counters in Redis that budgets are checked against are a
    cache of it, rebuilt from it. The application's database role may add rows and read them and
    nothing else, as for the audit log. `(kind, ref)` is unique, so a call recorded twice is counted
    once. `ts` is the moment the call began, which decides the window it is charged to."""

    __tablename__ = "spend_ledger"
    __table_args__ = (
        UniqueConstraint("kind", "ref", name="uq_spend_ledger_ref"),
        CheckConstraint(_in("kind", LEDGER_KINDS), name="ck_spend_ledger_kind"),
        Index("ix_spend_ledger_tenant_ts", "tenant_id", "ts"),
        Index("ix_spend_ledger_user_ts", "tenant_id", "user_id", "ts"),
        Index("ix_spend_ledger_agent_ts", "tenant_id", "agent_id", "ts"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # No foreign key to tenants, as in the audit log: the record of money outlives what it names.
    tenant_id: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[str] = mapped_column(Text, nullable=False)
    agent_id: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    # The call id of a tool call, or the id Keystone gave a model request.
    ref: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str | None] = mapped_column(Text)
    input_tokens: Mapped[int | None] = mapped_column(BigInteger)
    output_tokens: Mapped[int | None] = mapped_column(BigInteger)
    # No precision: a price must come back as the number that went in.
    cost_usd: Mapped[Decimal] = mapped_column(Numeric, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class BudgetRow(Base):
    """A spending limit (KS-805): `limit_usd` for `scope_id` of kind `scope`, over a `window`. The
    config file is the only source of these, applied at startup."""

    __tablename__ = "budgets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "scope", "scope_id", "window", name="uq_budgets_scope"),
        CheckConstraint(_in("scope", BUDGET_SCOPES), name="ck_budgets_scope"),
        # `window` is a reserved word in SQL, so the column is quoted wherever it is named in text.
        CheckConstraint(_in('"window"', BUDGET_WINDOWS), name="ck_budgets_window"),
        CheckConstraint("limit_usd > 0", name="ck_budgets_limit"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(Text, ForeignKey("tenants.id"), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    # The tenant's own id for the scope `tenant`; a user id or an agent id for the others.
    scope_id: Mapped[str] = mapped_column(Text, nullable=False)
    window: Mapped[str] = mapped_column(Text, nullable=False)
    limit_usd: Mapped[Decimal] = mapped_column(Numeric, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# The table, typed as one, for statements that must be a single UPDATE (`__table__` is a plain
# FromClause as far as the type checker knows).
APPROVALS = cast("Table", Approval.__table__)
