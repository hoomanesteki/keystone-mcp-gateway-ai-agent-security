"""The demo upstreams as the witnesses of a run (KS-901).

Before a run they are put in the state of the scenario, and after it they are asked what they did.
They are asked directly and not through Keystone: the test routes of the demo servers (`/_reset`,
`/_state`) are open and are not tools, so an agent cannot reach them, and what they say is what
happened on the upstream whatever the gateway reported.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from eval.redteam.schema import Upstream

TIMEOUT_S = 10.0
# The ports of the compose stack (`deploy/docker-compose.yml`).
COMPOSE_PORTS: dict[Upstream, int] = {"mail": 8101, "files": 8102, "bank": 8103, "web": 8105}


def local_urls(host: str = "localhost") -> dict[Upstream, str]:
    """The addresses of the demo upstreams of the compose stack, as this machine sees them."""
    return {name: f"http://{host}:{port}" for name, port in COMPOSE_PORTS.items()}


class Witness:
    def __init__(self, urls: Mapping[Upstream, str], *, timeout_s: float = TIMEOUT_S) -> None:
        self.urls = {name: base.rstrip("/") for name, base in urls.items()}
        self._timeout = timeout_s

    def reset(self, variant: str | None) -> None:
        """Put every upstream in the state of `variant`, or of the seed when there is none."""
        params = {"variant": variant} if variant else None
        with httpx.Client(timeout=self._timeout) as http:
            for base in self.urls.values():
                http.post(f"{base}/_reset", params=params).raise_for_status()

    def states(self) -> dict[str, dict[str, Any]]:
        with httpx.Client(timeout=self._timeout) as http:
            return {name: self._state(http, base) for name, base in self.urls.items()}

    async def areset(self, variant: str | None) -> None:
        params = {"variant": variant} if variant else None
        async with httpx.AsyncClient(timeout=self._timeout) as http:
            for base in self.urls.values():
                (await http.post(f"{base}/_reset", params=params)).raise_for_status()

    async def astates(self) -> dict[str, dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self._timeout) as http:
            found: dict[str, dict[str, Any]] = {}
            for name, base in self.urls.items():
                answer = await http.get(f"{base}/_state")
                answer.raise_for_status()
                found[name] = answer.json()
            return found

    @staticmethod
    def _state(http: httpx.Client, base: str) -> dict[str, Any]:
        answer = http.get(f"{base}/_state")
        answer.raise_for_status()
        state: dict[str, Any] = answer.json()
        return state
