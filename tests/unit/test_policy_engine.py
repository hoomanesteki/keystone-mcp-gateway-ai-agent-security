"""KS-404: the two-pass engine decides allow, deny or require approval, and fails closed."""

import statistics
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from bench_policy import fifty_policies

from keystone.core.types import (
    CallContext,
    Decision,
    Effect,
    Principal,
    Risk,
    SessionState,
    ToolRef,
    ToolTag,
)
from keystone.policy.engine import DEFAULT_DENY, POLICY_ERROR, CedarPolicyEngine
from keystone.policy.entities import Action, build_context
from keystone.policy.store import PolicyStore
from tests.fixtures.calls import make_ctx, make_tool
from tests.fixtures.policies import POLICY_ROOT, forbid, permit, write_policies

ALICE = Principal(tenant_id="acme", user_id="alice", groups=("support",), agent_id="support-agent")
OLIVIA = Principal(
    tenant_id="acme",
    user_id="olivia",
    groups=("operators",),
    agent_id="ops-agent",
    agent_trust="high",
)
MAIL = make_tool("mail", "read_email", risk=Risk.LOW)
TRANSFER = make_tool("bank", "transfer", risk=Risk.HIGH, tags=frozenset({ToolTag.EXTERNAL_EFFECT}))


def engine_for(
    tmp_path: Path, files: Mapping[str, str], tenants: tuple[str, ...] = ("acme",)
) -> CedarPolicyEngine:
    store = PolicyStore(write_policies(tmp_path / "policies", files), tenants)
    store.start()
    return CedarPolicyEngine(store)


def ask(
    engine: CedarPolicyEngine,
    principal: Principal = ALICE,
    tool: ToolRef = MAIL,
    action: Action = "call_tool",
    args: dict[str, int | str | bool] | None = None,
    call_count: int = 0,
) -> Decision:
    session = SessionState(
        session_id="s",
        principal=principal,
        call_count=call_count,
        created_at=make_ctx().received_at,
    )
    call: CallContext = make_ctx(tool=tool, principal=principal, session=session)
    return engine.evaluate(principal, action, tool, build_context(call, args or {}))


def decide(files: Mapping[str, str], tmp_path: Path, **kwargs: Any) -> Decision:
    return ask(engine_for(tmp_path, files), **kwargs)


@pytest.mark.phase(4)
def test_permit_gives_allow_with_reasons(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path, {"default/access/a.cedar": permit("allow-low", "resource.risk_level <= 2")}
    )

    decision = ask(engine)

    assert (decision.effect, decision.reasons, decision.source) == (
        Effect.ALLOW,
        ["allow-low"],
        "policy",
    )
    assert decision.policy_version == engine.version
    assert 0 < decision.evaluated_ms < 1000


@pytest.mark.phase(4)
def test_forbid_overrides_permit(tmp_path: Path) -> None:
    files = {
        "default/access/a.cedar": permit("allow-everything")
        + forbid("never-for-alice", 'principal == Keystone::User::"acme:alice"'),
    }

    decision = decide(files, tmp_path)

    assert (decision.effect, decision.reasons) == (Effect.DENY, ["never-for-alice"])


@pytest.mark.phase(4)
def test_no_match_default_deny(tmp_path: Path) -> None:
    files = {"default/access/a.cedar": permit("operators-only", "false")}

    decision = decide(files, tmp_path)

    assert (decision.effect, decision.reasons) == (Effect.DENY, [DEFAULT_DENY])
    assert decision.source == "policy" and decision.policy_version


@pytest.mark.phase(4)
def test_approval_set_upgrades(tmp_path: Path) -> None:
    files = {
        "default/access/a.cedar": permit("allow-everything"),
        "acme/approval/bank.cedar": permit(
            "approve-big-transfers", "context.args has amount && context.args.amount > 500"
        ),
    }
    engine = engine_for(tmp_path, files)

    small = ask(engine, args={"amount": 100})
    big = ask(engine, args={"amount": 900})
    none = ask(engine)

    assert (small.effect, small.reasons) == (Effect.ALLOW, ["allow-everything"])
    assert (big.effect, big.reasons) == (Effect.REQUIRE_APPROVAL, ["approve-big-transfers"])
    assert (none.effect, none.reasons) == (Effect.ALLOW, ["allow-everything"])


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    "files",
    [
        pytest.param(
            {
                "default/access/a.cedar": permit("allow-everything")
                + forbid("overflows", "context.call_count + 9223372036854775807 > 0"),
            },
            id="a forbid that fails to evaluate does not forbid",
        ),
        pytest.param(
            {
                "default/access/a.cedar": permit("allow-everything"),
                "default/approval/a.cedar": permit(
                    "overflows", "context.call_count + 9223372036854775807 > 0"
                ),
            },
            id="an approval permit that fails to evaluate does not ask",
        ),
        pytest.param(
            {
                "default/access/a.cedar": permit(
                    "overflows", "context.call_count + 9223372036854775807 > 0"
                )
            },
            id="the only permit fails to evaluate",
        ),
    ],
)
def test_evaluation_error_fails_closed(tmp_path: Path, files: dict[str, str]) -> None:
    engine = engine_for(tmp_path, files)

    decision = ask(engine, call_count=5)

    assert (decision.effect, decision.reasons) == (Effect.DENY, [POLICY_ERROR])
    assert decision.source == "policy" and decision.policy_version == engine.version


@pytest.mark.phase(4)
def test_a_request_the_schema_refuses_is_a_policy_error(tmp_path: Path) -> None:
    files = {"default/access/a.cedar": permit("allow-everything")}

    decision = decide(files, tmp_path, args={"to": "someone"})  # `to` is not an args field

    assert (decision.effect, decision.reasons) == (Effect.DENY, [POLICY_ERROR])


@pytest.mark.phase(4)
def test_a_tenant_without_policies_and_a_store_with_nothing_loaded_are_policy_errors(
    tmp_path: Path,
) -> None:
    engine = engine_for(tmp_path, {"default/access/a.cedar": permit("allow-everything")})
    stranger = ALICE.model_copy(update={"tenant_id": "zed"})
    elsewhere = MAIL.model_copy(update={"tenant_id": "zed"})
    unloaded = CedarPolicyEngine(PolicyStore(tmp_path / "policies", ["acme"]))

    not_known = ask(engine, principal=stranger, tool=elsewhere)
    not_loaded = ask(unloaded)

    assert (not_known.effect, not_known.reasons) == (Effect.DENY, [POLICY_ERROR])
    assert (not_loaded.effect, not_loaded.reasons) == (Effect.DENY, [POLICY_ERROR])
    assert not_loaded.policy_version is None


@pytest.mark.phase(4)
def test_an_exception_inside_cedar_is_a_policy_error_and_is_logged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    engine = engine_for(tmp_path, {"default/access/a.cedar": permit("allow-everything")})

    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("cedar fell over")

    monkeypatch.setattr("keystone.policy.engine.authorize", boom)

    decision = ask(engine)

    assert (decision.effect, decision.reasons) == (Effect.DENY, [POLICY_ERROR])
    assert "policy_evaluation_crashed" in capsys.readouterr().out


@pytest.mark.phase(4)
def test_the_log_names_the_failing_policy_by_its_id(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    files = {
        "default/access/a.cedar": permit("allow-everything")
        + forbid("overflows", "context.call_count + 9223372036854775807 > 0"),
    }

    ask(engine_for(tmp_path, files), call_count=5)

    out = capsys.readouterr().out
    assert "policy_evaluation_failed" in out and "`overflows`" in out
    assert "policy1" not in out  # Cedar's own numbering is translated


@pytest.mark.phase(4)
def test_a_listing_stops_after_the_access_pass(tmp_path: Path) -> None:
    files = {
        "default/access/a.cedar": permit("allow-everything"),
        "default/approval/a.cedar": permit("ask-for-everything"),
    }
    engine = engine_for(tmp_path, files)

    listing = ask(engine, action="list_tool")
    call = ask(engine, action="call_tool")

    assert (listing.effect, listing.reasons) == (Effect.ALLOW, ["allow-everything"])
    assert (call.effect, call.reasons) == (Effect.REQUIRE_APPROVAL, ["ask-for-everything"])


@pytest.mark.phase(4)
def test_the_approval_pass_does_not_run_when_access_denies(tmp_path: Path) -> None:
    # A broken approval permit would be a policy error if it were asked. It is not asked, so the
    # answer is the plain default deny.
    files = {
        "default/access/a.cedar": permit("operators-only", "false"),
        "default/approval/a.cedar": permit(
            "overflows", "context.call_count + 9223372036854775807 > 0"
        ),
    }

    decision = decide(files, tmp_path, call_count=5)

    assert (decision.effect, decision.reasons) == (Effect.DENY, [DEFAULT_DENY])


@pytest.mark.phase(4)
def test_each_tenant_is_decided_by_its_own_set(tmp_path: Path) -> None:
    files = {
        "default/access/a.cedar": permit("allow-everything"),
        "acme/access/b.cedar": forbid("acme-freeze"),
    }
    engine = engine_for(tmp_path, files, tenants=("acme", "globex"))
    globex_user = ALICE.model_copy(update={"tenant_id": "globex"})
    globex_tool = MAIL.model_copy(update={"tenant_id": "globex"})

    acme = ask(engine)
    globex = ask(engine, principal=globex_user, tool=globex_tool)

    assert (acme.effect, acme.reasons) == (Effect.DENY, ["acme-freeze"])
    assert (globex.effect, globex.reasons) == (Effect.ALLOW, ["allow-everything"])


@pytest.mark.phase(4)
def test_reasons_are_sorted_and_the_trace_has_both_passes(tmp_path: Path) -> None:
    files = {
        "default/access/a.cedar": permit("zeta-rule") + permit("alpha-rule"),
        "default/approval/a.cedar": permit("ask-b") + permit("ask-a"),
    }
    engine = engine_for(tmp_path, files)
    session = SessionState(session_id="s", principal=ALICE, created_at=make_ctx().received_at)

    traced = engine.trace(ALICE, "call_tool", MAIL, build_context(session, {}))

    assert traced.decision.reasons == ["ask-a", "ask-b"]
    assert traced.access == ("alpha-rule", "zeta-rule")
    assert traced.approval == ("ask-a", "ask-b")


@pytest.mark.phase(4)
async def test_a_reload_changes_the_answer_and_the_version_of_the_same_engine(
    tmp_path: Path,
) -> None:
    root = write_policies(
        tmp_path / "policies", {"default/access/a.cedar": permit("allow-everything")}
    )
    store = PolicyStore(root, ["acme"])
    store.start()
    engine = CedarPolicyEngine(store)
    before = ask(engine)

    (root / "default" / "access" / "a.cedar").write_text(forbid("freeze"))
    await store.reload()
    after = ask(engine)

    assert before.effect is Effect.ALLOW and after.effect is Effect.DENY
    assert before.policy_version != after.policy_version == engine.version


@pytest.mark.phase(4)
def test_the_shipped_pack_decides_as_the_plan_says() -> None:
    store = PolicyStore(POLICY_ROOT, ["acme", "globex"])
    store.start()
    engine = CedarPolicyEngine(store)
    medium = make_tool("bank", "get_balance", risk=Risk.MEDIUM)
    critical = make_tool("admin", "wipe", risk=Risk.CRITICAL)
    admin = Principal(tenant_id="acme", user_id="root", groups=("admins",), agent_id="ops-agent")

    assert ask(engine, ALICE, MAIL).reasons == ["same-tenant-low-medium"]
    assert ask(engine, ALICE, medium).reasons == ["same-tenant-low-medium"]
    assert ask(engine, ALICE, TRANSFER).reasons == [DEFAULT_DENY]
    assert ask(engine, OLIVIA, TRANSFER).reasons == ["operators-high"]
    assert ask(engine, OLIVIA, critical).reasons == [DEFAULT_DENY]
    assert ask(engine, admin, critical).reasons == ["admins-critical"]
    other = TRANSFER.model_copy(update={"tenant_id": "globex"})
    assert ask(engine, OLIVIA, other).reasons == ["deny-cross-tenant"]


@pytest.mark.phase(4)
def test_eval_latency_budget(tmp_path: Path) -> None:
    store = PolicyStore(write_policies(tmp_path / "policies", fifty_policies()), ["acme"])
    store.start()
    engine = CedarPolicyEngine(store)
    assert len(store.current.tenants["acme"].policies) >= 50
    for _ in range(100):  # warm up
        ask(engine, OLIVIA, TRANSFER, args={"amount": 900})

    samples = []
    for i in range(1_000):
        started = time.perf_counter()
        decision = ask(engine, OLIVIA, TRANSFER, args={"amount": 50 + i % 20})
        samples.append((time.perf_counter() - started) * 1000)

    samples.sort()
    p50 = statistics.median(samples)
    p95 = samples[int(0.95 * (len(samples) - 1))]
    assert decision.effect is Effect.ALLOW
    # Two passes through 50 policies, the entities and the context built on each call. The budget
    # is the plan's (p95 under 5 ms in CI); a laptop is well inside it (docs/spikes/cedarpy.md).
    assert p95 < 5.0, f"p50 {p50:.2f} ms, p95 {p95:.2f} ms"
