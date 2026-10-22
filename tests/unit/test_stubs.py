import pytest

from keystone.core.errors import Code, Reject
from keystone.core.types import Decision, Effect
from keystone.gateway.stubs import ApprovalInterceptor, OutputScanInterceptor, PolicyInterceptor
from tests.fixtures.calls import make_ctx


@pytest.mark.phase(1)
async def test_stub_policy_allows_with_source_stub() -> None:
    ctx = make_ctx()

    await PolicyInterceptor().before_call(ctx)

    assert ctx.decision is not None
    assert (ctx.decision.effect, ctx.decision.source) == (Effect.ALLOW, "stub")


@pytest.mark.phase(1)
async def test_stub_approval_refuses_when_approval_is_required() -> None:
    ctx = make_ctx(decision=Decision(effect=Effect.REQUIRE_APPROVAL, source="policy"))

    with pytest.raises(Reject) as raised:
        await ApprovalInterceptor().before_call(ctx)

    assert raised.value.code is Code.DENIED
    assert raised.value.message == "approval not available"


@pytest.mark.phase(1)
async def test_stub_approval_ignores_allowed_calls() -> None:
    await ApprovalInterceptor().before_call(make_ctx())
    await ApprovalInterceptor().before_call(
        make_ctx(decision=Decision(effect=Effect.ALLOW, source="stub"))
    )


@pytest.mark.phase(1)
async def test_stub_scan_passes() -> None:
    ctx = make_ctx()

    await OutputScanInterceptor().after_call(ctx)

    assert ctx.scan is not None
    assert (ctx.scan.label, ctx.scan.action, ctx.scan.score) == ("benign", "pass", 0.0)
