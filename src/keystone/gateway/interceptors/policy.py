"""The policy slot and the policy-filtered tool list (KS-406).

`PolicyInterceptor` decides every call. It extracts the arguments a policy may read, builds the
entities and the context, asks the engine and records the decision on the call. A deny is refused
here, before any credential is opened or any upstream is reached. A `require_approval` is recorded
and passed on: the approval slot after this one decides what happens next.

`PolicyToolFilter` decides what a caller sees. It asks the engine about `list_tool` for each tool
and keeps the answers per (caller, policy version) for a while, in Redis when there is one. A tool
is still decided again when it is called: the list is a convenience, not the gate.
"""

from __future__ import annotations

import json
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Protocol

import anyio
import structlog
from redis.asyncio import Redis

from keystone.core.canonical import canonical_json, sha256_hex
from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, Decision, Effect, Principal, SessionState, ToolRef
from keystone.gateway.hooks import noop_hook
from keystone.policy.engine import PolicyEngine
from keystone.policy.entities import build_context
from keystone.policy.extractors import extract
from keystone.registry.naming import is_virtual

log = structlog.get_logger()

# The reason on the decision of a tool that Keystone serves itself.
VIRTUAL_REASON = "virtual-tool"
CACHE_PREFIX = "ks:policy:listcache"
CACHE_TIMEOUT_S = 1.0
MEMORY_CACHE_ENTRIES = 1_000
# Per tool: (a digest of what the decision depended on, whether the caller may see it).
Answers = dict[str, tuple[str, bool]]


class PolicyInterceptor:
    name = "policy"

    def __init__(self, engine: PolicyEngine) -> None:
        self._engine = engine

    async def before_call(self, ctx: CallContext) -> None:
        if is_virtual(ctx.tool):
            # keystone__whoami and keystone__await_approval are Keystone's own: Cedar has no rule
            # about them. The await tool runs the call that waited through the pipeline again, and
            # that call is decided by the policy like any other (KS-603).
            ctx.decision = Decision(effect=Effect.ALLOW, reasons=[VIRTUAL_REASON], source="virtual")
            return
        ctx.extracted = extract(ctx.arguments, ctx.tool.extractors)
        context = build_context(ctx, ctx.extracted)
        decision = self._engine.evaluate(ctx.principal, "call_tool", ctx.tool, context)
        ctx.decision = decision
        if decision.effect is Effect.DENY:
            raise Reject(
                Code.DENIED,
                f"denied by policy: {', '.join(decision.reasons)}",
                # Under the keystone/ prefix so it reaches the result's own _meta (KS-193).
                {"keystone/reasons": list(decision.reasons)},
            )

    @noop_hook
    async def after_call(self, ctx: CallContext) -> None:
        return None


def principal_hash(principal: Principal) -> str:
    """Who is asking, as far as a decision can depend on it: tenant, user, groups, agent, trust
    and roles. Scopes are not part of it, and neither is the session: a listing does not depend
    on either."""
    return sha256_hex(
        canonical_json(
            [
                principal.tenant_id,
                principal.user_id,
                sorted(set(principal.groups)),
                principal.agent_id,
                principal.agent_trust,
                sorted(set(principal.roles)),
            ]
        )
    )[:32]


def tool_digest(tool: ToolRef) -> str:
    """What a listing decision about the tool depends on, so that a tool whose risk or tags
    changed is decided again even when the caller's answers are still cached."""
    return sha256_hex(
        canonical_json(
            [
                tool.name,
                tool.tenant_id,
                tool.upstream_id,
                tool.risk.value,
                sorted(tag.value for tag in tool.tags),
            ]
        )
    )[:16]


class ListCache(Protocol):
    async def get(self, key: str) -> Answers | None: ...

    async def put(self, key: str, answers: Answers, ttl_s: float) -> None: ...


def _encode(answers: Mapping[str, tuple[str, bool]]) -> str:
    return json.dumps({name: [digest, allowed] for name, (digest, allowed) in answers.items()})


def _decode(raw: str | bytes | None) -> Answers | None:
    """The answers in a cache entry, or None when it is not one. A malformed entry is ignored
    and replaced, never believed."""
    if raw is None:
        return None
    try:
        loaded = json.loads(raw)
        return {
            str(name): (str(digest), allowed)
            for name, (digest, allowed) in loaded.items()
            if isinstance(allowed, bool)
        }
    except (ValueError, TypeError, AttributeError):
        return None


class RedisListCache:
    """Keys are `ks:policy:listcache:{principal_hash}:{version}` (plan section 3.7). Redis being
    slow or down only means the answers are worked out again."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def get(self, key: str) -> Answers | None:
        try:
            with anyio.fail_after(CACHE_TIMEOUT_S):
                return _decode(await self._redis.get(key))
        except Exception as exc:
            log.warning("policy_list_cache_unavailable", error=type(exc).__name__)
            return None

    async def put(self, key: str, answers: Answers, ttl_s: float) -> None:
        if ttl_s <= 0:
            return
        try:
            with anyio.fail_after(CACHE_TIMEOUT_S):
                await self._redis.set(key, _encode(answers), px=max(1, int(ttl_s * 1000)))
        except Exception as exc:
            log.warning("policy_list_cache_unavailable", error=type(exc).__name__)


class MemoryListCache:
    """The same, in this process, for a deployment without Redis."""

    def __init__(
        self, max_entries: int = MEMORY_CACHE_ENTRIES, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._max = max_entries
        self._clock = clock
        self._entries: OrderedDict[str, tuple[float, str]] = OrderedDict()

    async def get(self, key: str) -> Answers | None:
        found = self._entries.get(key)
        if found is None or found[0] <= self._clock():
            self._entries.pop(key, None)
            return None
        return _decode(found[1])

    async def put(self, key: str, answers: Answers, ttl_s: float) -> None:
        if ttl_s <= 0:
            return
        self._entries[key] = (self._clock() + ttl_s, _encode(answers))
        self._entries.move_to_end(key)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)


class PolicyToolFilter:
    """Keeps the tools a principal may see (`list_tool` is allowed)."""

    def __init__(self, engine: PolicyEngine, cache: ListCache | None, ttl_s: float = 60.0) -> None:
        self._engine = engine
        self._cache = cache
        self._ttl_s = ttl_s

    async def visible(self, principal: Principal, tools: Sequence[ToolRef]) -> list[ToolRef]:
        # The key names the version the decisions are made under. Read once, so the answers
        # stored under it were made by it even if a reload lands in the middle.
        version = self._engine.version
        key = f"{CACHE_PREFIX}:{principal_hash(principal)}:{version}"
        cached = (await self._cache.get(key) if self._cache else None) or {}
        context = None
        answers: Answers = {}
        fresh = False
        for tool in tools:
            digest = tool_digest(tool)
            known = cached.get(tool.name)
            if known is not None and known[0] == digest:
                answers[tool.name] = known
                continue
            if context is None:
                session = SessionState(
                    session_id="listing", principal=principal, created_at=datetime.now(UTC)
                )
                context = build_context(session, {})
            decision = self._engine.evaluate(principal, "list_tool", tool, context)
            answers[tool.name] = (digest, decision.effect is Effect.ALLOW)
            fresh = True
        if fresh and self._cache is not None:
            await self._cache.put(key, answers, self._ttl_s)
        return [tool for tool in tools if answers[tool.name][1]]
