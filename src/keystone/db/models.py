from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    Numeric,
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
TRANSPORTS = ("http", "stdio", "container_stdio")
CREDENTIAL_MODES = ("none", "static", "per_user")
UPSTREAM_SOURCES = ("config", "cli")
UPSTREAM_STATUSES = ("unknown", "up", "degraded", "down", "disabled")
TOOL_STATUSES = ("active", "quarantined", "disabled")
RISKS = ("low", "medium", "high", "critical")


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
