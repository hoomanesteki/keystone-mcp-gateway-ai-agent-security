"""Watch the upstreams and stop sending calls to one that is down (KS-209).

Every `interval_s` each live upstream is probed. A failed probe moves it to `degraded`, and
`down_after` failures in a row move it to `down`. One good probe brings it back to `up`. While an
upstream is `down`, a call to it is refused at once instead of waiting out a connection timeout,
so one dead server does not tie up every agent that happens to call it. The probes go on while
it is down, which is how it comes back.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Literal, Protocol

import anyio
import structlog

from keystone.db.models import Upstream
from keystone.gateway.upstreams import UpstreamPool
from keystone.registry.repo import UpstreamStatus

log = structlog.get_logger()

HealthStatus = Literal["up", "degraded", "down"]

# Tells the directory where the upstreams are, so a probe can reach one added after startup.
Learn = Callable[[Sequence[Upstream]], Awaitable[None]]


class HealthStore(Protocol):
    """The part of the upstream repository the probes use."""

    async def list(
        self, tenant_id: str | None = None, *, include_disabled: bool = True
    ) -> Sequence[Upstream]: ...

    async def set_status_unless_disabled(
        self, upstream_id: str, status: UpstreamStatus
    ) -> bool: ...


class UpstreamHealth:
    def __init__(
        self,
        pool: UpstreamPool,
        upstreams: HealthStore,
        learn: Learn,
        *,
        interval_s: float = 30.0,
        timeout_s: float = 3.0,
        degraded_after: int = 1,
        down_after: int = 3,
    ) -> None:
        self._pool = pool
        self._upstreams = upstreams
        self._learn = learn
        self.interval_s = interval_s
        self._timeout_s = timeout_s
        self._degraded_after = degraded_after
        self._down_after = down_after
        self._failures: dict[str, int] = {}
        self._status: dict[str, HealthStatus] = {}

    def status(self, upstream_id: str) -> HealthStatus | None:
        """What the last probes say, or None before the first one."""
        return self._status.get(upstream_id)

    def is_down(self, upstream_id: str) -> bool:
        return self._status.get(upstream_id) == "down"

    def record(self, upstream_id: str, ok: bool) -> HealthStatus:
        """Count one probe result and return the upstream's new status."""
        failures = 0 if ok else self._failures.get(upstream_id, 0) + 1
        self._failures[upstream_id] = failures
        status: HealthStatus = "up"
        if failures >= self._down_after:
            status = "down"
        elif failures >= self._degraded_after:
            status = "degraded"
        before = self._status.get(upstream_id)
        self._status[upstream_id] = status
        # A first probe that finds the upstream healthy is not news. Every change after that is,
        # and so is a first probe that finds it unwell.
        if status != before and (before is not None or status != "up"):
            log.info("upstream_status", upstream=upstream_id, before=before, status=status)
        return status

    async def check_all(self) -> dict[str, HealthStatus]:
        """Probe every live upstream at once and store the results. Never raises."""
        try:
            rows = list(await self._upstreams.list(include_disabled=False))
            await self._learn(rows)
        except Exception as exc:
            log.warning("health_round_failed", error=type(exc).__name__)
            return {}
        live = {row.id for row in rows}
        for gone in set(self._status) - live:
            self._status.pop(gone, None)
            self._failures.pop(gone, None)

        results: dict[str, HealthStatus] = {}

        async def probe(upstream_id: str) -> None:
            results[upstream_id] = self.record(upstream_id, await self._probe(upstream_id))
            try:
                # Written every round, so the database converges on what the probes say even
                # after a sync wrote `up` on its own.
                await self._upstreams.set_status_unless_disabled(upstream_id, results[upstream_id])
            except Exception as exc:
                log.warning(
                    "health_status_not_stored", upstream=upstream_id, error=type(exc).__name__
                )

        async with anyio.create_task_group() as group:
            for upstream_id in sorted(live):
                group.start_soon(probe, upstream_id)
        return dict(sorted(results.items()))

    async def run(self) -> None:
        """Probe now, then every `interval_s`, until cancelled."""
        while True:
            await self.check_all()
            await anyio.sleep(self.interval_s)

    async def _probe(self, upstream_id: str) -> bool:
        try:
            with anyio.fail_after(self._timeout_s):
                async with self._pool.lease(upstream_id) as client:
                    return await client.health()
        except Exception:
            # TimeoutError, a Reject from a client that is closed, a factory that does not know
            # the upstream: none of them is an answer, so none counts as healthy.
            return False
