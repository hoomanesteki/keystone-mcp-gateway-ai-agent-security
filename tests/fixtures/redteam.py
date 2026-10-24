"""The four upstreams the red-team scenarios touch, each in a thread on a port of its own (KS-901).

The mail, files, bank and web servers are the demo ones, open to anyone, with a database and a
workspace under the test's folder. `reset(variant)` puts all four in the state of a scenario, and
`states()` asks them what they did, the way a run does (`eval/redteam/witness.py`).
"""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from eval.redteam.schema import Upstream
from eval.redteam.witness import Witness
from examples.upstreams import bank_server, files_server, mail_server, web_server
from tests.fixtures.servers import ServerThread


@dataclass
class RedTeamUpstreams:
    threads: dict[Upstream, ServerThread]

    @property
    def witness(self) -> Witness:
        return Witness({name: thread.url for name, thread in self.threads.items()})

    def mcp(self, name: Upstream) -> str:
        """The MCP endpoint of one upstream."""
        return f"{self.threads[name].url}/mcp"

    def reset(self, variant: str | None = None) -> None:
        self.witness.reset(variant)

    def states(self) -> dict[str, dict[str, Any]]:
        return self.witness.states()


@pytest.fixture(scope="module")
def redteam_upstreams(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RedTeamUpstreams]:
    root = tmp_path_factory.mktemp("redteam-upstreams")
    servers = {
        "mail": mail_server.create_server(root / "mail.db"),
        "files": files_server.create_server(root / "workspace", root / "files.db"),
        "bank": bank_server.create_server(root / "bank.db"),
        "web": web_server.create_server(),
    }
    threads: dict[Upstream, ServerThread] = {
        name: ServerThread(app.streamable_http_app()).start()  # type: ignore[misc]
        for name, app in servers.items()
    }
    started = RedTeamUpstreams(threads)
    try:
        yield started
    finally:
        for thread in threads.values():
            thread.stop()
