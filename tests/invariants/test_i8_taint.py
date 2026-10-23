"""I8: a tainted session never dispatches a critical-risk tool.

The real policy engine and the real slots (policy, output scan, flags) run in front of a dispatcher
that only counts. A session is tainted in every way there is: an injection in an output, an
injection in an error, the store marking it, a stale copy of the session saved over it. Then every
kind of caller (who may run a critical tool, and who may not) tries every kind of critical tool,
with the tags that matter. Nothing may reach the dispatcher.

The test is only worth something if it can see a dispatch, so the same callers and tools are tried
in a session that is not tainted first, and the admins get through there.

A tenant may add rules of its own, and the invariant must hold against a rule that permits
everything, because a forbid beats every permit. The part it leaves out is a call that is already
past the policy slot when the taint lands (ADR-0015): that call was issued before the output that
tainted the session came back, so the output could not have steered it.
"""

import itertools
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.types import (
    CallContext,
    Principal,
    Risk,
    SessionState,
    ToolRef,
    ToolResult,
    ToolTag,
)
from keystone.defense.scanner import OutputScanner
from keystone.gateway.pipeline import Pipeline
from keystone.gateway.sessions import InMemorySessionStore
from keystone.gateway.wiring import PipelineDeps, build_pipeline
from keystone.policy.engine import CedarPolicyEngine
from keystone.policy.store import PolicyStore
from keystone.settings import Settings
from tests.fixtures.calls import make_ctx, make_tool
from tests.fixtures.policies import copy_pack, permit, write_policies
from tests.fixtures.scan import INJECTION, guard

pytestmark = pytest.mark.phase(7)

SESSION = "session-1"
PRINCIPALS = {
    "support": Principal(
        tenant_id="acme", user_id="alice", groups=("support",), agent_id="support-agent"
    ),
    "operator": Principal(
        tenant_id="acme",
        user_id="olivia",
        groups=("operators",),
        agent_id="ops-agent",
        agent_trust="high",
    ),
    "admin": Principal(
        tenant_id="acme",
        user_id="root",
        groups=("admins",),
        agent_id="ops-agent",
        agent_trust="high",
        roles=("admin",),
    ),
    "both": Principal(
        tenant_id="acme",
        user_id="both",
        groups=("operators", "admins"),
        agent_id="ops-agent",
        agent_trust="high",
    ),
}
# Callers whom the access set lets run a critical tool when the session is not tainted.
MAY_RUN_CRITICAL = {"admin", "both"}
EVERY_TAG = frozenset(ToolTag)
CRITICAL = {
    "plain": make_tool("admin", "wipe", risk=Risk.CRITICAL, schema={"type": "object"}),
    "external": make_tool(
        "admin",
        "wire",
        risk=Risk.CRITICAL,
        tags=frozenset({ToolTag.EXTERNAL_EFFECT}),
        schema={"type": "object"},
    ),
    "reads": make_tool(
        "admin",
        "dump",
        risk=Risk.CRITICAL,
        tags=frozenset({ToolTag.READS_UNTRUSTED, ToolTag.READS_SENSITIVE}),
        schema={"type": "object"},
    ),
    "code": make_tool(
        "sandbox",
        "run_python",
        risk=Risk.CRITICAL,
        tags=frozenset({ToolTag.CODE_EXEC}),
        schema={"type": "object"},
    ),
    "all-tags": make_tool(
        "admin", "everything", risk=Risk.CRITICAL, tags=EVERY_TAG, schema={"type": "object"}
    ),
}
READER = make_tool(
    "mail",
    "read_email",
    risk=Risk.LOW,
    tags=frozenset({ToolTag.READS_UNTRUSTED, ToolTag.READS_SENSITIVE}),
    schema={"type": "object"},
)


class Counting:
    """The upstream. A read returns an injection, as an error or not, and a critical tool counts
    the times it is reached."""

    def __init__(self) -> None:
        self.dispatched: list[str] = []
        self.read_fails = False

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        self.dispatched.append(ctx.tool.name)
        if ctx.tool.name == READER.name:
            return ToolResult(
                content=[{"type": "text", "text": INJECTION}], is_error=self.read_fails
            )
        return ToolResult(content=[{"type": "text", "text": "done"}])

    def reached(self, tool: ToolRef) -> int:
        return self.dispatched.count(tool.name)


class World:
    """A pipeline over the real policies, one session store and the counting upstream."""

    def __init__(self, settings: Settings, policy_root: Path) -> None:
        store = PolicyStore(policy_root, ["acme", "globex"], include_demo=True)
        store.start()
        self.store = InMemorySessionStore()
        self.upstream = Counting()
        self.audit = InMemoryAuditSink()
        scanner: OutputScanner = guard()
        self.pipeline: Pipeline = build_pipeline(
            settings,
            PipelineDeps(
                dispatcher=self.upstream,
                audit=self.audit,
                policy=CedarPolicyEngine(store),
                sessions=self.store,
                scanner=scanner,
            ),
        )

    async def session_of(self, who: Principal) -> SessionState:
        return await self.store.get(SESSION) or await self.store.create(SESSION, who)

    async def call(self, who: Principal, tool: ToolRef) -> ToolResult:
        """A call as the gateway makes it: the session is read from the store at its start."""
        ctx = make_ctx({}, tool, principal=who, session=await self.session_of(who))
        return await self.pipeline.run(ctx)


async def read_an_injection(world: World, who: Principal) -> None:
    result = await world.call(who, READER)
    assert (await world.store.get(SESSION)) is not None  # the read happened in this session
    assert not result.is_error


async def read_an_injection_in_an_error(world: World, who: Principal) -> None:
    world.upstream.read_fails = True
    await world.call(who, READER)


async def mark_in_the_store(world: World, who: Principal) -> None:
    await world.session_of(who)
    await world.store.mark_tainted(SESSION)


async def mark_then_save_a_stale_copy(world: World, who: Principal) -> None:
    stale = await world.session_of(who)  # a copy from before the taint
    await world.store.mark_tainted(SESSION)
    await world.store.save(stale)  # written back late, when it says "not tainted"


TAINTS: dict[str, Callable[[World, Principal], Awaitable[None]]] = {
    "an injection in an output": read_an_injection,
    "an injection in an error": read_an_injection_in_an_error,
    "the store marks it": mark_in_the_store,
    "a stale copy saved over it": mark_then_save_a_stale_copy,
}


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    return copy_pack(tmp_path)


async def test_i8(settings: Settings, pack: Path) -> None:
    tried = 0
    for (name, who), (kind, tool) in itertools.product(PRINCIPALS.items(), CRITICAL.items()):
        # The control: with nothing wrong with the session, the admins run the tool.
        clean = World(settings, pack)
        await clean.session_of(who)
        await clean.call(who, tool)
        assert clean.upstream.reached(tool) == (1 if name in MAY_RUN_CRITICAL else 0), (name, kind)

        for how, taint in TAINTS.items():
            world = World(settings, pack)
            await world.session_of(who)
            await taint(world, who)
            stored = await world.store.get(SESSION)
            assert stored is not None and stored.tainted, (name, kind, how)

            result = await world.call(who, tool)

            tried += 1
            assert world.upstream.reached(tool) == 0, (name, kind, how)
            assert result.is_error, (name, kind, how)
            decided = world.audit.records[-1]
            assert decided["dispatched"] is False and decided["decision"] == "deny", (
                name,
                kind,
                how,
            )
    assert tried == len(PRINCIPALS) * len(CRITICAL) * len(TAINTS)


async def test_i8_holds_against_a_rule_that_permits_everything(
    settings: Settings, pack: Path
) -> None:
    # A tenant that adds a permit-all rule, in either set, cannot open the door: the forbid wins.
    write_policies(pack, {"acme/access/open.cedar": permit("open-to-all")})
    admin = PRINCIPALS["admin"]
    world = World(settings, pack)
    await world.session_of(admin)
    await mark_in_the_store(world, admin)

    for tool in CRITICAL.values():
        await world.call(admin, tool)
        assert world.upstream.reached(tool) == 0, tool.name

    # The same rule does open the door to a session that is not tainted, so it was a real rule.
    clean = World(settings, pack)
    await clean.session_of(admin)
    await clean.call(admin, CRITICAL["plain"])
    assert clean.upstream.reached(CRITICAL["plain"]) == 1


async def test_i8_the_taint_survives_every_attempt_to_clear_it(
    settings: Settings, pack: Path
) -> None:
    admin = PRINCIPALS["admin"]
    world = World(settings, pack)
    await world.session_of(admin)
    await read_an_injection(world, admin)

    clean_copy = SessionState(
        session_id=SESSION, principal=admin, created_at=(await world.session_of(admin)).created_at
    )
    await world.store.save(clean_copy)  # a copy that says clean and has no flags
    await world.store.create(SESSION, admin)  # a session opened again under the same id
    await world.store.touch(SESSION)
    await world.store.add_flags(SESSION, [])
    await world.call(admin, CRITICAL["plain"])

    assert world.upstream.reached(CRITICAL["plain"]) == 0
    kept = await world.store.get(SESSION)
    assert kept is not None and kept.tainted
