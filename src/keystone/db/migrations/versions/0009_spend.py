"""spend: the ledger of what was spent, and the budgets it is checked against

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "spend_ledger",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("ref", sa.Text(), nullable=False),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column("input_tokens", sa.BigInteger(), nullable=True),
        sa.Column("output_tokens", sa.BigInteger(), nullable=True),
        sa.Column("cost_usd", sa.Numeric(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("kind", "ref", name="uq_spend_ledger_ref"),
        sa.CheckConstraint("kind IN ('tool', 'llm')", name="ck_spend_ledger_kind"),
    )
    op.create_index("ix_spend_ledger_tenant_ts", "spend_ledger", ["tenant_id", "ts"])
    op.create_index("ix_spend_ledger_user_ts", "spend_ledger", ["tenant_id", "user_id", "ts"])
    op.create_index("ix_spend_ledger_agent_ts", "spend_ledger", ["tenant_id", "agent_id", "ts"])
    op.create_table(
        "budgets",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("scope_id", sa.Text(), nullable=False),
        sa.Column("window", sa.Text(), nullable=False),
        sa.Column("limit_usd", sa.Numeric(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "scope", "scope_id", "window", name="uq_budgets_scope"),
        sa.CheckConstraint("scope IN ('tenant', 'user', 'agent')", name="ck_budgets_scope"),
        # `window` is a reserved word in SQL, so the column is quoted wherever it is named in text.
        sa.CheckConstraint("\"window\" IN ('day', 'month')", name="ck_budgets_window"),
        sa.CheckConstraint("limit_usd > 0", name="ck_budgets_limit"),
    )
    # The application role reaches both tables through the default privileges of 0006. The ledger
    # is the record of money, like the audit log is the record of calls: the application may add to
    # it and read it, and nothing else. A gateway that is compromised cannot take spend back out.
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON spend_ledger FROM keystone_app")


def downgrade() -> None:
    op.drop_table("budgets")
    op.drop_table("spend_ledger")
