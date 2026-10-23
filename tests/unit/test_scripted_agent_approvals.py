"""KS-603: what the scripted agent does when Keystone answers KS_APPROVAL_PENDING.

A stand-in for the MCP client records the calls and gives the answers a test lists, so the rules
can be read without a gateway: one await by itself, none for a step that expects the pending
answer, and the outstanding id for a step that awaits without naming one.
"""

from typing import Any

import mcp_types as types
import pytest

from examples.agents.scripted_agent import (
    AWAIT_TOOL,
    Outstanding,
    Step,
    run_step,
    settle_pending,
)

pytestmark = pytest.mark.phase(6)

TRANSFER = Step("bank__transfer", {"amount": 900})
ID = "01JAPPROVAL"


def success(text: str = '{"status": "completed"}') -> types.CallToolResult:
    return types.CallToolResult.model_validate(
        {"content": [{"type": "text", "text": text}], "isError": False}
    )


def refusal(code: str, text: str = "no", **meta: object) -> types.CallToolResult:
    keys = {"keystone/code": code, **meta}
    return types.CallToolResult.model_validate(
        {
            "content": [{"type": "text", "text": f"[keystone:{code}] {text}", "_meta": keys}],
            "isError": True,
            "_meta": keys,
        }
    )


def pending(approval_id: str = ID) -> types.CallToolResult:
    return refusal("KS_APPROVAL_PENDING", "wait", **{"keystone/approval_id": approval_id})


class Client:
    def __init__(self, *answers: types.CallToolResult) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> types.ListToolsResult:
        raise NotImplementedError

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult:
        self.calls.append((name, dict(arguments or {})))
        return self.answers.pop(0)


async def test_a_pending_answer_is_waited_for_once_with_the_id_it_carries() -> None:
    client = Client(pending(), success())
    outstanding = Outstanding()

    entry = await run_step(client, 1, TRANSFER, outstanding)

    assert client.calls == [("bank__transfer", {"amount": 900}), (AWAIT_TOOL, {"approval_id": ID})]
    assert entry.ok and entry.awaited == ID
    assert "completed" in entry.text
    assert outstanding.approval_id is None  # decided, so nothing is outstanding


async def test_the_id_is_read_from_the_block_when_the_result_has_none() -> None:
    meta = {"keystone/code": "KS_APPROVAL_PENDING", "keystone/approval_id": ID}
    block_only = types.CallToolResult.model_validate(
        {
            "content": [
                {"type": "text", "text": "[keystone:KS_APPROVAL_PENDING] w", "_meta": meta}
            ],
            "isError": True,
        }
    )
    client = Client(block_only, success())

    entry = await run_step(client, 1, TRANSFER, Outstanding())

    assert client.calls[1] == (AWAIT_TOOL, {"approval_id": ID}) and entry.ok


async def test_a_step_that_expects_the_pending_answer_is_not_waited_for() -> None:
    client = Client(pending())
    outstanding = Outstanding()
    step = Step("bank__transfer", {"amount": 900}, expect_error_code="KS_APPROVAL_PENDING")

    entry = await run_step(client, 1, step, outstanding)

    assert len(client.calls) == 1
    assert entry.ok and entry.awaited is None and entry.error_code == "KS_APPROVAL_PENDING"
    assert outstanding.approval_id == ID  # remembered for a step that awaits


async def test_an_await_that_is_still_pending_fails_the_step_and_stays_outstanding() -> None:
    client = Client(pending(), pending())
    outstanding = Outstanding()

    entry = await run_step(client, 1, TRANSFER, outstanding)

    assert len(client.calls) == 2  # once, and no more
    assert not entry.ok and entry.awaited == ID and entry.error_code == "KS_APPROVAL_PENDING"
    assert outstanding.approval_id == ID


async def test_a_step_that_awaits_without_an_id_waits_for_the_outstanding_one() -> None:
    client = Client(success())
    outstanding = Outstanding(approval_id=ID)

    entry = await run_step(client, 2, Step(AWAIT_TOOL), outstanding)

    assert client.calls == [(AWAIT_TOOL, {"approval_id": ID})]
    assert entry.ok and entry.arguments == {"approval_id": ID}
    assert outstanding.approval_id is None


async def test_a_step_that_awaits_with_nothing_outstanding_passes_without_a_call() -> None:
    client = Client()

    entry = await run_step(client, 2, Step(AWAIT_TOOL), Outstanding())

    assert client.calls == []
    assert entry.ok and "nothing to wait for" in entry.text


async def test_a_step_that_names_the_id_is_called_as_written() -> None:
    client = Client(success())

    entry = await run_step(
        client,
        2,
        Step(AWAIT_TOOL, {"approval_id": "01JOTHER", "wait_seconds": 5}),
        Outstanding(approval_id=ID),
    )

    assert client.calls == [(AWAIT_TOOL, {"approval_id": "01JOTHER", "wait_seconds": 5})]
    assert entry.ok


@pytest.mark.parametrize("code", ["KS_DENIED", "KS_APPROVAL_REJECTED", "KS_APPROVAL_EXPIRED"])
async def test_other_refusals_are_not_waited_for(code: str) -> None:
    client = Client(refusal(code))

    entry = await run_step(client, 1, TRANSFER, Outstanding())

    assert len(client.calls) == 1
    assert not entry.ok and entry.error_code == code and entry.awaited is None


async def test_settle_pending_is_the_one_wait_other_agents_can_borrow() -> None:
    """The naive agent of Phase 7 calls this to get the same behavior."""
    client = Client(success())

    result, awaited = await settle_pending(client, pending())

    assert awaited == ID and not result.is_error
    assert client.calls == [(AWAIT_TOOL, {"approval_id": ID})]

    untouched, none = await settle_pending(Client(), success())
    assert none is None and not untouched.is_error
