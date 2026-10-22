from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from keystone.core.errors import Code, Reject, to_tool_result
from keystone.core.ids import new_id
from keystone.core.types import (
    RISK_LEVEL,
    CallContext,
    Principal,
    Risk,
    SessionState,
    ToolRef,
    ToolResult,
)


def make_principal() -> Principal:
    return Principal(
        tenant_id="acme", user_id="olivia", groups=("operators",), agent_id="ops-agent"
    )


@pytest.mark.phase(1)
def test_principal_is_frozen() -> None:
    principal = make_principal()

    with pytest.raises(ValidationError):
        principal.tenant_id = "globex"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        principal.groups = ()  # type: ignore[misc]


@pytest.mark.phase(1)
def test_reject_to_tool_result_format() -> None:
    reject = Reject(Code.DENIED, "policy forbids transfers", {"policy": "no-transfers"})

    result = to_tool_result(reject, "01JABCDEF")

    assert isinstance(result, ToolResult)
    assert result.is_error is True
    assert len(result.content) == 1
    block = result.content[0]
    assert block["type"] == "text"
    assert block["text"] == "[keystone:KS_DENIED] call 01JABCDEF denied: policy forbids transfers"
    assert block["_meta"] == {
        "keystone/code": "KS_DENIED",
        "keystone/call_id": "01JABCDEF",
        "policy": "no-transfers",
    }


@pytest.mark.phase(1)
def test_reject_data_cannot_overwrite_the_code() -> None:
    reject = Reject(Code.RATE_LIMITED, "slow down", {"keystone/code": "KS_DENIED"})

    block = to_tool_result(reject, "01JX").content[0]

    assert block["_meta"]["keystone/code"] == "KS_RATE_LIMITED"
    assert block["text"].startswith("[keystone:KS_RATE_LIMITED] call 01JX ")


@pytest.mark.phase(1)
@pytest.mark.parametrize("code", list(Code))
def test_every_code_has_a_text_prefix(code: Code) -> None:
    block = to_tool_result(Reject(code, "why"), "01JX").content[0]

    assert block["text"].startswith(f"[keystone:{code.value}] call 01JX ")
    assert block["text"].endswith(": why")


@pytest.mark.phase(1)
def test_risk_levels_are_ordered() -> None:
    assert [RISK_LEVEL[r] for r in (Risk.LOW, Risk.MEDIUM, Risk.HIGH, Risk.CRITICAL)] == [
        1,
        2,
        3,
        4,
    ]


@pytest.mark.phase(1)
def test_call_context_defaults() -> None:
    principal = make_principal()
    now = datetime.now(UTC)
    tool = ToolRef(
        name="mail__read_email",
        upstream_id="mail",
        upstream_tool_name="read_email",
        tenant_id="acme",
        description="Read one email",
        input_schema={"type": "object"},
        description_hash="d",
        schema_hash="s",
    )
    session = SessionState(session_id="s1", principal=principal, created_at=now)

    ctx = CallContext(
        call_id=new_id(),
        received_at=now,
        principal=principal,
        session=session,
        tool=tool,
        arguments={},
    )

    assert ctx.decision is None
    assert ctx.result is None
    assert ctx.dispatched is False
    assert ctx.upstream_headers == {}
    assert tool.risk is Risk.MEDIUM


@pytest.mark.phase(1)
def test_new_id_is_a_sortable_ulid() -> None:
    ids = [new_id() for _ in range(5000)]

    assert all(len(i) == 26 for i in ids)
    assert len(set(ids)) == len(ids)
    assert ids == sorted(ids)
    assert set("".join(ids)) <= set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
