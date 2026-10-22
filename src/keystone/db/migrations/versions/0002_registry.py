"""registry: upstreams, tools and sessions

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-21
"""

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _created_at() -> sa.Column[datetime]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        "upstreams",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("transport", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("command", postgresql.JSONB(none_as_null=True), nullable=True),
        sa.Column("image", sa.Text(), nullable=True),
        sa.Column("credential_mode", sa.Text(), server_default="none", nullable=False),
        sa.Column("source", sa.Text(), server_default="config", nullable=False),
        sa.Column("status", sa.Text(), server_default="unknown", nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        _created_at(),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_upstreams_tenant_id_id"),
        sa.CheckConstraint(
            "transport IN ('http', 'stdio', 'container_stdio')", name="ck_upstreams_transport"
        ),
        sa.CheckConstraint(
            "credential_mode IN ('none', 'static', 'per_user')", name="ck_upstreams_credential"
        ),
        sa.CheckConstraint("source IN ('config', 'cli')", name="ck_upstreams_source"),
        sa.CheckConstraint(
            "status IN ('unknown', 'up', 'degraded', 'down', 'disabled')",
            name="ck_upstreams_status",
        ),
    )
    op.create_table(
        "tools",
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("upstream_id", sa.Text(), nullable=False),
        sa.Column("upstream_tool_name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("input_schema", postgresql.JSONB(), nullable=False),
        sa.Column("risk", sa.Text(), server_default="medium", nullable=False),
        sa.Column(
            "tags", postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False
        ),
        sa.Column("cost_per_call_usd", sa.Numeric(), server_default=sa.text("0"), nullable=False),
        sa.Column("timeout_s", sa.Float(), server_default=sa.text("30"), nullable=False),
        sa.Column(
            "extractors",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("description_hash", sa.Text(), nullable=False),
        sa.Column("schema_hash", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="active", nullable=False),
        sa.Column("pending_description", sa.Text(), nullable=True),
        sa.Column("pending_schema", postgresql.JSONB(none_as_null=True), nullable=True),
        sa.Column("quarantine_reason", sa.Text(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(
            ["tenant_id", "upstream_id"],
            ["upstreams.tenant_id", "upstreams.id"],
            name="fk_tools_upstream",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "name"),
        sa.CheckConstraint(
            "status IN ('active', 'quarantined', 'disabled')", name="ck_tools_status"
        ),
        sa.CheckConstraint("risk IN ('low', 'medium', 'high', 'critical')", name="ck_tools_risk"),
    )
    op.create_index("ix_tools_upstream", "tools", ["tenant_id", "upstream_id"])
    op.create_table(
        "sessions",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "final_flags",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("tainted", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("sessions")
    op.drop_index("ix_tools_upstream", table_name="tools")
    op.drop_table("tools")
    op.drop_table("upstreams")
