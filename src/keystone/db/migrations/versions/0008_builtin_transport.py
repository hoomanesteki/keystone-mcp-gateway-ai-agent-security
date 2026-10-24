"""upstreams: allow the transport builtin, for the sandbox

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-23
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BEFORE = "transport IN ('http', 'stdio', 'container_stdio')"
AFTER = "transport IN ('http', 'stdio', 'container_stdio', 'builtin')"


def upgrade() -> None:
    op.drop_constraint("ck_upstreams_transport", "upstreams", type_="check")
    op.create_check_constraint("ck_upstreams_transport", "upstreams", AFTER)


def downgrade() -> None:
    # A built-in upstream cannot exist under the old constraint. Its tools and credentials go with
    # it; audit records name upstreams by id and need no row.
    op.execute(
        "DELETE FROM credentials WHERE upstream_id IN "
        "(SELECT id FROM upstreams WHERE transport = 'builtin')"
    )
    op.execute(
        "DELETE FROM tools WHERE upstream_id IN "
        "(SELECT id FROM upstreams WHERE transport = 'builtin')"
    )
    op.execute("DELETE FROM upstreams WHERE transport = 'builtin'")
    op.drop_constraint("ck_upstreams_transport", "upstreams", type_="check")
    op.create_check_constraint("ck_upstreams_transport", "upstreams", BEFORE)
