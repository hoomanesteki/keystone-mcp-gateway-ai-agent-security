"""approvals: requests for a person to approve a tool call

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The application role reaches this table through the default privileges that 0006 set, so
    # it may read and write every column. `args_ciphertext` is the plan's section 3.7 plus one
    # column: the original arguments, encrypted, so that an approved call runs with exactly them.
    op.create_table(
        "approvals",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("call_id", sa.Text(), nullable=False),
        sa.Column("tool_name", sa.Text(), nullable=False),
        sa.Column("args_redacted", postgresql.JSONB(none_as_null=True), nullable=False),
        sa.Column("args_digest", sa.Text(), nullable=False),
        sa.Column("args_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column(
            "reasons",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("requested_by_user", sa.Text(), nullable=False),
        sa.Column("requested_by_agent", sa.Text(), nullable=False),
        sa.Column("decided_by", sa.Text(), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column(
            "requested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'consumed')",
            name="ck_approvals_status",
        ),
    )
    op.create_index("ix_approvals_tenant_status", "approvals", ["tenant_id", "status"])
    op.create_index("ix_approvals_session", "approvals", ["tenant_id", "session_id"])


def downgrade() -> None:
    op.drop_table("approvals")
