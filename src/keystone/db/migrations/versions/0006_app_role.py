"""app_role: the database role Keystone runs as, which can add audit records but not change them

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-23
"""

import os
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLE = "keystone_app"
# Development only: the password of the role in the local stack. It is in .env.example and the
# compose file, and tests/unit/test_dev_secrets.py fails if the three differ.
DEV_PASSWORD = "keystone-app-dev-password"  # noqa: S105 - development only


def password() -> str:
    """KEYSTONE_APP_DB_PASSWORD, or the development password. A prod deployment must set its own,
    or the role would be created with a password that is public."""
    given = os.environ.get("KEYSTONE_APP_DB_PASSWORD")
    if given:
        return given
    if os.environ.get("KEYSTONE_ENV") == "prod":
        raise RuntimeError(
            "set KEYSTONE_APP_DB_PASSWORD before the migration that creates the keystone_app role"
        )
    return DEV_PASSWORD


def upgrade() -> None:
    bind = op.get_bind()
    # Roles belong to the cluster, not to one database, so the role may already exist from another
    # database (the tests make several). Then its password stays as it is: change it with
    # ALTER ROLE.
    exists = bind.execute(sa.text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": ROLE})
    if exists.first() is None:
        # Postgres quotes the password, so no character in it can end the literal.
        statement = bind.execute(
            sa.text(
                "SELECT format('CREATE ROLE keystone_app LOGIN PASSWORD %L', CAST(:pw AS text))"
            ),
            {"pw": password()},
        ).scalar_one()
        bind.exec_driver_sql(statement)
    op.execute(f"GRANT USAGE ON SCHEMA public TO {ROLE}")
    # Every table that exists now, and every table a later migration makes (default privileges
    # apply to objects created by the role that runs this migration).
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {ROLE}")
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {ROLE}")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {ROLE}"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {ROLE}"
    )
    # The log is append only for the application: it may add and read records and nothing else.
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM {ROLE}")
    # The application has no business with the migration state.
    op.execute(f"REVOKE ALL ON alembic_version FROM {ROLE}")


def downgrade() -> None:
    op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {ROLE}")
    op.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {ROLE}")
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM {ROLE}")
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM {ROLE}")
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {ROLE}")
    # The role is the cluster's, and other databases may still grant it something. It is dropped
    # only when nothing else depends on it.
    op.execute(
        "DO $$ BEGIN DROP ROLE IF EXISTS keystone_app; "
        "EXCEPTION WHEN dependent_objects_still_exist THEN NULL; END $$"
    )
