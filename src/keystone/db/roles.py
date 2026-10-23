"""The database role the application runs as (KS-503, ADR-0009).

Migrations run as the role that owns the tables. Keystone runs as `keystone_app`, which has full
access to every table except `audit_events`, where it may only add and read records. A gateway that
is compromised cannot edit what it logged.
"""

APP_ROLE = "keystone_app"

# Development only. The migration that creates the role uses it when KEYSTONE_APP_DB_PASSWORD is not
# set, and it is the default in the compose file and in .env.example. Setting env to prod without a
# password stops the migration.
DEV_APP_PASSWORD = "keystone-app-dev-password"  # noqa: S105 - development only
