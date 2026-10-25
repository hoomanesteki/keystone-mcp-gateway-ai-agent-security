"""The rate limit slot: calls come as fast as the buckets allow (KS-804).

It is the first slot, so a call that is going to be refused for any other reason still takes its
token. That is on purpose. A flood of calls that the policy would deny, or that would each create
an approval request, is a flood, and the limit is what stops it (the gate of Phase 6 found that
nothing limited how many approval requests an agent could make).

Every call counts, Keystone's own tools included: `keystone__whoami` and
`keystone__await_approval` are calls like the rest, and an agent that polls the await tool in a
loop is as much a loop as one that polls a mail server. A call the await tool runs after an
approval does not count a second time. It carries the id of the approval (only the await tool puts
one there), it was counted when it first arrived, and the await was counted as the call it is.

A call is checked against every scope that is set, in the order tenant, user, agent, tool, and
refused by the first bucket with no token. Nothing is taken from any bucket when one refuses.
`retry_after_s` is the wait for that bucket; a client that waits it may meet the next scope.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable

import structlog

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect
from keystone.gateway.hooks import noop_hook
from keystone.metering.ratelimit import (
    KEY_PREFIX,
    Bucket,
    RateLimiter,
    Verdict,
    whole_milliseconds,
)
from keystone.settings import RateLimitSettings
from keystone.telemetry.metrics import Metrics

log = structlog.get_logger()

# A key is made of identifiers that come from a token. A long one is replaced by its hash, so that
# a key stays short and a user id cannot be made long enough to matter.
MAX_ID_CHARS = 128

# What the agent reads. The key of the scope is for the log and for programs.
WHO = {
    "per_tenant": "your organization's",
    "per_user": "your user's",
    "per_agent": "this agent's",
    "per_tool": "this tool's",
}


def _id(value: str) -> str:
    if len(value) <= MAX_ID_CHARS:
        return value
    return hashlib.sha256(value.encode()).hexdigest()


class RateLimitInterceptor:
    name = "rate_limit"

    def __init__(
        self,
        limiter: RateLimiter,
        limits: RateLimitSettings,
        *,
        metrics: Metrics | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._limiter = limiter
        self._limits = limits.scopes()
        self._metrics = metrics
        self._clock = clock

    def _buckets(self, ctx: CallContext, *, with_tool: bool = True) -> list[Bucket]:
        principal, tenant = ctx.principal, ctx.principal.tenant_id
        # The tenant is in every key, so two tenants never share a bucket, whatever their users
        # are called.
        names = {
            "per_tenant": tenant,
            "per_user": f"{tenant}:{_id(principal.user_id)}",
            "per_agent": f"{tenant}:{_id(principal.agent_id)}",
            "per_tool": f"{tenant}:{_id(ctx.tool.name)}",
        }
        return [
            Bucket(scope, f"{KEY_PREFIX}{scope}:{names[scope]}", limit.capacity, limit.refill_per_s)
            for scope, limit in self._limits
            if with_tool or scope != "per_tool"
        ]

    async def before_call(self, ctx: CallContext) -> None:
        if ctx.approval_id or not self._limits:
            return
        verdict = await self._limiter.check(self._buckets(ctx), self._clock())
        if verdict.allowed:
            return
        raise self._refusal(ctx, verdict)

    async def charge_principal(self, ctx: CallContext, *, with_tool: bool = False) -> None:
        """Take a token from the principal's buckets, and with `with_tool` from the tool's, for a
        call refused before this slot ran: the tool it names does not exist (KS-992), its arguments
        fit no schema, its session cannot be read (KS-998). The tool's bucket is left alone for a
        name that is no tool. Raises the same Reject as `before_call` when a bucket is empty. An
        agent that loops on such calls is audited on every one and is limited as well."""
        buckets = self._buckets(ctx, with_tool=with_tool)
        if not buckets:
            return
        verdict = await self._limiter.check(buckets, self._clock())
        if not verdict.allowed:
            raise self._refusal(ctx, verdict)

    def _refusal(self, ctx: CallContext, verdict: Verdict) -> Reject:
        scope = verdict.scope or "per_user"
        retry = whole_milliseconds(verdict.retry_after_s)
        self._count(ctx, scope)
        ctx.decision = Decision(
            effect=Effect.DENY, reasons=[f"rate-limit:{scope}"], source="rate_limit"
        )
        return Reject(
            Code.RATE_LIMITED,
            f"too many calls: {WHO.get(scope, 'a')} limit is used up, "
            f"try again in {max(retry, 0.1):.1f} seconds",
            {
                "scope": scope,
                "retry_after_s": retry,
                # Only keys with this prefix reach the metadata of the result itself.
                "keystone/scope": scope,
                "keystone/retry_after_s": retry,
            },
        )

    @noop_hook
    async def after_call(self, ctx: CallContext) -> None:
        return None

    def _count(self, ctx: CallContext, scope: str) -> None:
        if self._metrics is None:
            return
        try:
            self._metrics.rate_limit_refused(ctx.principal.tenant_id, scope)
        except Exception:
            log.error("metrics_failed", exc_info=True)
