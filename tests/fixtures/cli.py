"""Run the `keystone` command against the test database."""

from typing import Any

import anyio
from typer.testing import CliRunner

from keystone.admin.cli import app as cli


async def invoke(database_url: str, args: list[str], **env: str) -> Any:
    """Run one command and return typer's result. The command starts its own event loop, so it
    runs in a worker thread and not on the test's loop."""
    environment = {
        "KEYSTONE_DATABASE_URL": database_url,
        "KEYSTONE_ALLOW_PRIVATE_UPSTREAMS": "true",
        **env,
    }
    return await anyio.to_thread.run_sync(lambda: CliRunner().invoke(cli, args, env=environment))
