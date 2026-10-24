import pytest

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.types import CallContext, Effect, ToolResult
from keystone.gateway.interceptors.approval import ApprovalInterceptor as RealApprovalInterceptor
from keystone.gateway.interceptors.flags import SessionFlagsInterceptor
from keystone.gateway.interceptors.policy import PolicyInterceptor
from keystone.gateway.interceptors.scan import OutputScanInterceptor
from keystone.gateway.sessions import InMemorySessionStore
from keystone.gateway.stubs import ApprovalInterceptor
from keystone.gateway.stubs import OutputScanInterceptor as StubOutputScanInterceptor
from keystone.gateway.wiring import INTERCEPTOR_ORDER, PipelineDeps, build_pipeline
from keystone.settings import ScannerSettings, Settings
from tests.fixtures.calls import make_ctx
from tests.fixtures.scan import guard


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


@pytest.mark.phase(4)
def test_with_an_engine_the_policy_slot_is_the_real_interceptor(settings: Settings) -> None:
    class Engine:
        version = "v"

        def evaluate(self, *args: object) -> None:
            raise AssertionError("not asked in this test")

    with_engine = PipelineDeps(
        dispatcher=Echoing(),
        audit=InMemoryAuditSink(),
        policy=Engine(),  # type: ignore[arg-type]
    )

    real = build_pipeline(settings, with_engine)
    stub = build_pipeline(settings, deps())

    slot = INTERCEPTOR_ORDER.index("policy")
    assert isinstance(real.interceptors[slot], PolicyInterceptor)
    assert not isinstance(stub.interceptors[slot], PolicyInterceptor)


@pytest.mark.phase(6)
def test_with_an_approval_service_the_approval_slot_is_the_real_interceptor(
    settings: Settings,
) -> None:
    class Service:
        pass

    with_approvals = PipelineDeps(
        dispatcher=Echoing(),
        audit=InMemoryAuditSink(),
        approvals=Service(),  # type: ignore[arg-type]
    )

    real = build_pipeline(settings, with_approvals)
    stub = build_pipeline(settings, deps())

    slot = INTERCEPTOR_ORDER.index("approval")
    assert isinstance(real.interceptors[slot], RealApprovalInterceptor)
    assert type(stub.interceptors[slot]) is ApprovalInterceptor  # the stub, which refuses


@pytest.mark.phase(7)
def test_with_a_scanner_the_output_slot_is_the_real_interceptor(settings: Settings) -> None:
    real = build_pipeline(
        settings,
        PipelineDeps(dispatcher=Echoing(), audit=InMemoryAuditSink(), scanner=guard()),
    )
    stub = build_pipeline(settings, deps())

    slot = INTERCEPTOR_ORDER.index("output_scan")
    assert isinstance(real.interceptors[slot], OutputScanInterceptor)
    assert type(stub.interceptors[slot]) is StubOutputScanInterceptor  # scans nothing


@pytest.mark.phase(7)
async def test_a_scanner_that_is_switched_off_leaves_a_slot_that_records_no_scan(
    settings: Settings,
) -> None:
    off = settings.model_copy(update={"scanner": ScannerSettings(enabled=False)})
    ctx = make_ctx({"text": "hi"})

    pipeline = build_pipeline(
        off, PipelineDeps(dispatcher=Echoing(), audit=InMemoryAuditSink(), scanner=guard())
    )
    await pipeline.run(ctx)

    # The audit record of a call that was not scanned has no score, and does not say "pass".
    assert isinstance(
        pipeline.interceptors[INTERCEPTOR_ORDER.index("output_scan")], OutputScanInterceptor
    )
    assert ctx.scan is None


@pytest.mark.phase(7)
async def test_the_flags_slot_is_the_real_interceptor_with_or_without_a_store(
    settings: Settings,
) -> None:
    slot = INTERCEPTOR_ORDER.index("session_flags")

    without = build_pipeline(settings, deps())
    with_store = build_pipeline(
        settings,
        PipelineDeps(
            dispatcher=Echoing(), audit=InMemoryAuditSink(), sessions=InMemorySessionStore()
        ),
    )

    assert isinstance(without.interceptors[slot], SessionFlagsInterceptor)
    assert isinstance(with_store.interceptors[slot], SessionFlagsInterceptor)


# -- the passthrough profile (KS-902)


@pytest.mark.phase(9)
def test_the_profile_is_full_unless_it_is_set() -> None:
    assert Settings().profile == "full"
    assert Settings(profile="passthrough").profile == "passthrough"
    with pytest.raises(ValueError, match="profile"):
        Settings.model_validate({"profile": "off"})


@pytest.mark.phase(9)
@pytest.mark.parametrize("env", ["dev", "test"])
def test_the_passthrough_profile_is_allowed_where_the_baseline_is_measured(env: str) -> None:
    assert Settings(env=env, profile="passthrough").profile == "passthrough"  # type: ignore[arg-type]


@pytest.mark.phase(9)
def test_the_passthrough_profile_is_refused_in_production() -> None:
    # A stray variable must not be able to turn every defense off in a deployment.
    with pytest.raises(ValueError, match="defends nothing"):
        Settings(env="prod", profile="passthrough")
    assert Settings(env="prod", profile="full").profile == "full"


@pytest.mark.phase(9)
def test_the_passthrough_pipeline_keeps_its_order_and_only_the_credentials_are_real(
    settings: Settings,
) -> None:
    from keystone.gateway import stubs
    from keystone.gateway.interceptors.credentials import CredentialInterceptor

    pipeline = build_pipeline(settings.model_copy(update={"profile": "passthrough"}), deps())

    assert [i.name for i in pipeline.interceptors] == list(INTERCEPTOR_ORDER)
    for slot in pipeline.interceptors:
        if slot.name == "credential":
            # What Keystone sends an upstream to be let in is not a defense, and a baseline that
            # lost it could not reach the demo servers.
            assert isinstance(slot, CredentialInterceptor)
        elif slot.name == "output_scan":
            # The slot with no scanner, so that the audit record has no scan to report.
            assert isinstance(slot, OutputScanInterceptor) and slot._guard is None
        else:
            assert type(slot).__module__ == stubs.__name__, slot.name


@pytest.mark.phase(9)
def test_the_passthrough_profile_ignores_what_a_full_pipeline_would_be_given(
    settings: Settings,
) -> None:
    from keystone.defense.scanner import build_scanner_guard

    given = PipelineDeps(
        dispatcher=Echoing(),
        audit=InMemoryAuditSink(),
        scanner=build_scanner_guard(ScannerSettings(classifier="none")),
        sessions=InMemorySessionStore(),
    )
    scan = INTERCEPTOR_ORDER.index("output_scan")
    flags = INTERCEPTOR_ORDER.index("session_flags")

    full = build_pipeline(settings.model_copy(update={"profile": "full"}), given)
    baseline = build_pipeline(settings.model_copy(update={"profile": "passthrough"}), given)

    scanning = full.interceptors[scan]
    assert isinstance(scanning, OutputScanInterceptor) and scanning._guard is not None
    assert isinstance(full.interceptors[flags], SessionFlagsInterceptor)
    silent = baseline.interceptors[scan]
    assert isinstance(silent, OutputScanInterceptor) and silent._guard is None
    assert not isinstance(baseline.interceptors[flags], SessionFlagsInterceptor)


@pytest.mark.phase(9)
async def test_a_passthrough_call_reaches_the_upstream_and_leaves_its_audit_record(
    settings: Settings,
) -> None:
    audit = InMemoryAuditSink()
    pipeline = build_pipeline(
        settings.model_copy(update={"profile": "passthrough"}),
        PipelineDeps(dispatcher=Echoing(), audit=audit),
    )
    ctx = make_ctx({"text": "hi"})

    result = await pipeline.run(ctx)

    assert result.content == [{"type": "text", "text": "hi"}]
    assert ctx.scan is None  # nothing was scanned, and the record does not say it was
    # The audit record is the pipeline's, not a slot's, so the baseline has one for each call.
    assert len(audit.records) == 1
