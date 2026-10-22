import json

import pytest

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.errors import Code, Reject
from tests.fixtures.calls import make_ctx


@pytest.mark.phase(1)
async def test_record_holds_identifiers_and_never_arguments() -> None:
    sink = InMemoryAuditSink()
    ctx = make_ctx({"text": "card 4111 1111 1111 1111"})

    await sink.record(ctx, "rejected", Reject(Code.DENIED, "no"))

    [record] = sink.records
    assert record["call_id"] == ctx.call_id
    assert (record["tenant_id"], record["user_id"], record["agent_id"]) == (
        "acme",
        "olivia",
        "ops-agent",
    )
    assert record["tool"] == "echo__echo"
    assert (record["outcome"], record["reject_code"]) == ("rejected", "KS_DENIED")
    assert "4111" not in json.dumps(record, default=str)
