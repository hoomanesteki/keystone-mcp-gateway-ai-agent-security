"""audit_events: the append-only, hash-chained audit log

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # `ts` is the time of the call and replaces created_at: a time the database chose would sit
    # outside the hash. `seq` is a bigserial, but the writer assigns it (ADR-0009): a rolled-back
    # batch must not leave a hole, and verify reads a hole as a deleted record.
    op.create_table(
        "audit_events",
        sa.Column("seq", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("call_id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("tool_name", sa.Text(), nullable=False),
        sa.Column("effect", sa.Text(), nullable=True),
        # Which part decided: policy, pinning, a rate limit. The plan's list of columns is the key
        # ones, and this and `dispatched` are added to it (ADR-0009).
        sa.Column("decision_source", sa.Text(), nullable=True),
        sa.Column(
            "reasons",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("policy_version", sa.Text(), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("reject_code", sa.Text(), nullable=True),
        sa.Column("dispatched", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("args_redacted", postgresql.JSONB(none_as_null=True), nullable=True),
        sa.Column("args_digest", sa.Text(), nullable=True),
        sa.Column("scan_score", sa.Numeric(), nullable=True),
        sa.Column("scan_action", sa.Text(), nullable=True),
        sa.Column("cost_usd", sa.Numeric(), server_default=sa.text("0"), nullable=False),
        sa.Column("latency_ms", sa.Numeric(), nullable=True),
        sa.Column("trace_id", sa.Text(), nullable=True),
        sa.Column("prev_hash", sa.Text(), nullable=False),
        sa.Column("hash", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("seq"),
        # Two records cannot follow the same one, so a fork of the chain is refused by the
        # database even if the advisory lock were ever bypassed.
        sa.UniqueConstraint("prev_hash", name="uq_audit_events_prev_hash"),
        sa.CheckConstraint(
            "effect IS NULL OR effect IN ('allow', 'deny', 'require_approval')",
            name="ck_audit_events_effect",
        ),
        sa.CheckConstraint(
            "outcome IN ('ok', 'rejected', 'error')", name="ck_audit_events_outcome"
        ),
    )
    op.create_index("ix_audit_events_tenant_seq", "audit_events", ["tenant_id", "seq"])
    op.create_index("ix_audit_events_tenant_ts", "audit_events", ["tenant_id", "ts"])
    op.create_index("ix_audit_events_call_id", "audit_events", ["call_id"])


def downgrade() -> None:
    op.drop_table("audit_events")
