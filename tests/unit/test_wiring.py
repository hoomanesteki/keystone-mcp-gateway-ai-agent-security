import pytest

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.types import CallContext, Effect, ToolResult
from keystone.gateway.stubs import ApprovalInterceptor
from keystone.gateway.wiring import INTERCEPTOR_ORDER, PipelineDeps, build_pipeline
from keystone.settings import Settings
from tests.fixtures.calls import make_ctx


class Echoing:
    async def dispatch(self, ctx: CallContext) -> ToolResult:
        return ToolResult(content=[{"type": "text", "text": ctx.arguments["text"]}])


def deps() -> PipelineDeps:
    return PipelineDeps(dispatcher=Echoing(), audit=InMemoryAuditSink())


@pytest.mark.phase(1)
def test_default_pipeline_has_the_fixed_order(settings: Settings) -> None:
    pipeline = build_pipeline(settings, deps())

    assert INTERCEPTOR_ORDER == (
        "rate_limit",
        "pinning",
        "budget",
        "policy",
        "approval",
        "credential",
        "output_scan",
        "session_flags",
        "metering",
    )
    assert [i.name for i in pipeline.interceptors] == list(INTERCEPTOR_ORDER)


@pytest.mark.phase(1)
async def test_stub_pipeline_allows_and_scans(settings: Settings) -> None:
    ctx = make_ctx({"text": "hi"})

    result = await build_pipeline(settings, deps()).run(ctx)

    assert result.content == [{"type": "text", "text": "hi"}]
    assert ctx.decision is not None
    assert (ctx.decision.effect, ctx.decision.source) == (Effect.ALLOW, "stub")
    assert ctx.scan is not None
    assert ctx.scan.action == "pass"


@pytest.mark.phase(1)
def test_an_override_replaces_one_slot_and_keeps_the_order(settings: Settings) -> None:
    class Custom(ApprovalInterceptor):
        pass

    custom = Custom()

    pipeline = build_pipeline(settings, deps(), {"approval": custom})

    assert pipeline.interceptors[INTERCEPTOR_ORDER.index("approval")] is custom
    assert [i.name for i in pipeline.interceptors] == list(INTERCEPTOR_ORDER)


@pytest.mark.phase(1)
def test_an_unknown_override_is_an_error(settings: Settings) -> None:
    with pytest.raises(ValueError, match="polcy"):
        build_pipeline(settings, deps(), {"polcy": ApprovalInterceptor()})
