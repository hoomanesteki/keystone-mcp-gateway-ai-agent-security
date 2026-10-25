"""KS-902: the model-driven agent end to end, with no key.

The model is the fake one in its agent mode (examples/fake_llm): `fake-agent` makes the calls of a
script in the prompt and obeys a marker it reads in a tool result. Its requests go through the real
gateway's LLM proxy, so the loop, the metering of the proxy (a row of the ledger for each request)
and the stop at a budget are all exercised by the code that a run with a real model would use.
"""

import json
from collections.abc import Callable, Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from examples.agents.llm_agent import LlmRun, run_llm_agent, to_anthropic
from examples.upstreams import mail_server
from keystone.registry.config import UpstreamConfig
from keystone.settings import BudgetConfig
from tests.fixtures.approvals import Approver
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.fake_llm import FakeLlm
from tests.fixtures.keystone import KeystoneApp, demo_tools
from tests.fixtures.servers import ServerThread

pytestmark = [pytest.mark.phase(9), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
MODEL = "fake-agent"
READ_TWO = [
    {"tool": "mail__list_emails", "args": {"unread_only": True}},
    {"tool": "mail__read_email", "args": {"email_id": "m02"}},
]


def prompt(steps: list[dict[str, Any]], words: str = "Summarize my unread emails.") -> str:
    return f"{words} <!--ks-script:{json.dumps(steps)}-->"


def start(factory: Factory, fake: FakeLlm, prices: Path, **settings: Any) -> KeystoneApp:
    return factory(
        settings={"llm_proxy": fake.settings(prices), **settings}, environ=fake.environ()
    )


async def run(
    app: KeystoneApp, idp: FakeIdp, steps: list[dict[str, Any]], **options: Any
) -> LlmRun:
    return await run_llm_agent(
        app.url,
        f"{app.base}/llm/anthropic",
        idp.token_for("olivia"),
        prompt(steps),
        model=options.pop("model", MODEL),
        **options,
    )


async def ledger(app: KeystoneApp) -> list[Any]:
    engine = create_async_engine(app.database_url, poolclass=NullPool)
    try:
        async with engine.begin() as connection:
            rows = await connection.execute(
                text("SELECT * FROM spend_ledger WHERE kind = 'llm' ORDER BY ts, id")
            )
            return list(rows.mappings())
    finally:
        await engine.dispose()


async def test_the_loop_calls_the_tools_of_the_script_and_every_request_is_booked(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Path
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    result = await run(app, fake_idp, READ_TWO)

    # Two calls and then the answer: three requests of the model.
    assert result.stopped == "done" and result.turns == 3
    assert [c.tool for c in result.calls] == ["mail__list_emails", "mail__read_email"]
    assert not any(c.is_error for c in result.calls)
    assert "Brightline" in result.results and result.output == "Done."
    assert len(result.request_ids) == 3
    # The ledger has a row for each request, under the id Keystone gave it, and its tokens are the
    # ones the answers reported: the cost of a run is a sum over rows that can be checked.
    rows = await ledger(app)
    assert sorted(r["ref"] for r in rows) == sorted(result.request_ids)
    assert sum(r["input_tokens"] for r in rows) == result.input_tokens > 0
    assert sum(r["output_tokens"] for r in rows) == result.output_tokens == 36
    assert {r["model"] for r in rows} == {MODEL} and all(r["cost_usd"] > 0 for r in rows)
    assert {(r["user_id"], r["agent_id"]) for r in rows} == {("olivia", "ops-agent")}


async def test_the_tools_are_given_to_the_model_in_its_own_format(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Path
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    await run(app, fake_idp, READ_TWO)

    [first, *_] = fake_llm.requests()
    body = first["body"]
    names = {tool["name"] for tool in body["tools"]}
    assert {"mail__read_email", "mail__send_email", "keystone__await_approval"} <= names
    send = next(t for t in body["tools"] if t["name"] == "mail__send_email")
    assert send["input_schema"]["properties"].keys() >= {"to", "subject", "body"}
    assert set(send) == {"name", "description", "input_schema"}
    # A neutral system prompt, the first message is the user's, and the key is Keystone's token.
    assert "inject" not in body["system"].lower()
    assert body["messages"][0]["role"] == "user" and body["model"] == MODEL
    assert first["key_ok"] is True  # the fake's own key, added by the proxy


async def test_the_loop_stops_after_the_turns_it_is_allowed(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Path
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)
    endless = [{"tool": "keystone__whoami", "args": {"n": n}} for n in range(10)]

    result = await run(app, fake_idp, endless, max_turns=4)

    assert result.stopped == "max_turns" and result.turns == 4
    assert len(result.calls) == 4 and len(await ledger(app)) == 4


async def test_a_model_with_no_price_ends_the_run_refused_and_costs_nothing(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Path
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    result = await run(app, fake_idp, READ_TWO, model="mystery-agent")

    assert result.stopped == "refused" and result.turns == 1 and result.calls == []
    assert result.detail == "the proxy answered 400 (KS_MODEL_NOT_PRICED)"
    assert await ledger(app) == [] and fake_llm.requests() == []


async def test_a_budget_stops_the_loop_before_the_model_is_asked(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Path
) -> None:
    broke = BudgetConfig(
        tenant="acme", scope="user", scope_id="olivia", window="day", limit_usd=Decimal("0.0001")
    )
    app = start(keystone_app_factory, fake_llm, fake_prices, budgets=[broke])

    result = await run(app, fake_idp, READ_TWO)

    # The request is refused as too dear before the provider sees it, and 402 is not retried.
    assert result.stopped == "budget" and result.turns == 1
    assert result.detail == "the proxy answered 402 (KS_BUDGET_EXCEEDED)"
    assert result.refusal is not None and result.refusal["scope"] == "user"
    assert Decimal(str(result.refusal["limit_usd"])) == Decimal("0.0001")
    assert Decimal(str(result.refusal["estimate_usd"])) > Decimal("0.0001")
    assert fake_llm.requests() == [] and await ledger(app) == []


async def test_a_budget_that_runs_out_during_the_run_stops_it_where_it_is(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Path
) -> None:
    # What one request is estimated at is read from a refusal. A limit a little over it lets the
    # first request in, and the second, which carries the first answer and costs a little more to
    # estimate, is over what is left.
    tiny = BudgetConfig(
        tenant="acme", scope="user", scope_id="olivia", window="day", limit_usd=Decimal("0.0001")
    )
    asked = await run(
        start(keystone_app_factory, fake_llm, fake_prices, budgets=[tiny]), fake_idp, READ_TWO
    )
    assert asked.refusal is not None
    estimate = Decimal(str(asked.refusal["estimate_usd"]))
    limit = estimate + Decimal("0.0004")
    app = start(
        keystone_app_factory,
        fake_llm,
        fake_prices,
        budgets=[
            BudgetConfig(
                tenant="acme", scope="agent", scope_id="ops-agent", window="day", limit_usd=limit
            )
        ],
    )

    result = await run(app, fake_idp, READ_TWO)

    assert result.stopped == "budget" and result.turns == 2
    assert len(result.calls) == 1 and result.calls[0].tool == "mail__list_emails"
    [row] = await ledger(app)  # the one request that was made is booked, and only that one
    assert row["ref"] == result.request_ids[0]
    assert result.refusal is not None and result.refusal["scope"] == "agent"


@pytest.fixture
def poisoned_mail(tmp_path: Path) -> Iterator[ServerThread]:
    server = mail_server.create_server(tmp_path / "mail.db", poisoned=True)
    thread = ServerThread(server.streamable_http_app()).start()
    yield thread
    thread.stop()


async def test_a_model_that_obeys_what_it_reads_is_held_by_the_gateway_like_any_agent(
    keystone_app_factory: Factory,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Path,
    poisoned_mail: ServerThread,
    approver: Approver,
) -> None:
    mail = UpstreamConfig(
        id="mail", tenant="acme", url=f"{poisoned_mail.url}/mcp", tools=demo_tools("mail")
    )
    app = start(keystone_app_factory, fake_llm, fake_prices, upstreams=[mail])
    read_the_poisoned_one = [{"tool": "mail__read_email", "args": {"email_id": "m13"}}]

    # The approver turns down whatever reaches the queue, as in the headline demo.
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(approver.reject, "nobody asked for this")
        result = await run(app, fake_idp, read_the_poisoned_one)

    # The model read the email, did what it said, and was told no. Then it was done.
    assert result.stopped == "done"
    assert [c.tool for c in result.calls] == ["mail__read_email", "mail__send_email"]
    assert result.error_codes == ["KS_APPROVAL_REJECTED"]
    assert result.calls[1].arguments["to"] == "attacker@evil.test"
    async with httpx.AsyncClient(timeout=10) as http:
        state = (await http.get(f"{poisoned_mail.url}/_state")).json()
    assert state["sent"] == []


def test_an_mcp_tool_becomes_a_tool_of_the_messages_api() -> None:
    import mcp_types as types

    tool = types.Tool(
        name="bank__transfer",
        description="Move money.",
        input_schema={"type": "object", "properties": {"amount": {"type": "number"}}},
    )
    bare = types.Tool(name="keystone__whoami", input_schema={"type": "object"})

    assert to_anthropic(tool) == {
        "name": "bank__transfer",
        "description": "Move money.",
        "input_schema": {"type": "object", "properties": {"amount": {"type": "number"}}},
    }
    assert to_anthropic(bare)["description"] == ""
