"""KS-806 through the running gateway, Postgres and Redis: model requests that go through Keystone.

The provider is the fake model API (examples/fake_llm) on a port of its own, and it wants a key, so
a request that reached it without the vault's key would be refused and the test would see the 401.
A prompt of four words and a reply of twelve cost $0.000192 at the fake prices of
tests/fixtures/fake_llm.py, and the tests work every other number out from that table.
"""

import asyncio
import io
import json
import logging
import time
from collections.abc import Callable, Iterator
from decimal import Decimal
from typing import Any

import httpx
import pytest
import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from keystone.logging import SECRETS, configure_logging
from keystone.registry.config import ToolOverride, UpstreamConfig
from keystone.settings import BudgetConfig
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.fake_llm import COST_OF_ONE_CALL, PROMPT, FakeLlm
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.tracing import dump, named, traced
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(8), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
API = "/admin/api/v1"
ANTHROPIC = "/llm/anthropic/v1/messages"
OPENAI = "/llm/openai/v1/chat/completions"
ONE_CALL = Decimal(COST_OF_ONE_CALL)


def body(model: str = "fake-model", **extra: Any) -> dict[str, Any]:
    return {
        "model": model,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": PROMPT}],
        **extra,
    }


@pytest.fixture(autouse=True)
def fresh_registry() -> Iterator[None]:
    SECRETS.clear()
    yield
    SECRETS.clear()


@pytest.fixture
def log_buffer(caplog: pytest.LogCaptureFixture) -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    configure_logging("DEBUG", stream=buffer)
    caplog.set_level(logging.DEBUG)
    yield buffer
    structlog.reset_defaults()


def log_events(buffer: io.StringIO, event: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in buffer.getvalue().splitlines() if line.startswith("{")]
    return [line for line in lines if line.get("event") == event]


def start(
    factory: Factory,
    fake: FakeLlm,
    prices: Any,
    *,
    llm: dict[str, Any] | None = None,
    environ: dict[str, str] | None = None,
    settings: dict[str, Any] | None = None,
    **options: Any,
) -> KeystoneApp:
    """An app whose proxy forwards to the fake. `llm` changes the proxy's settings, `settings` the
    app's, `environ` replaces the environment the provider keys are read from (the fake's key in
    both variables by default), and other keywords go to the factory."""
    return factory(
        settings={"llm_proxy": fake.settings(prices, **(llm or {})), **(settings or {})},
        environ=fake.environ() if environ is None else environ,
        **options,
    )


def post(
    app: KeystoneApp,
    token: str | None,
    path: str = ANTHROPIC,
    payload: Any = None,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    sent = dict(headers or {})
    if token is not None:
        sent["Authorization"] = f"Bearer {token}"
    return httpx.post(
        f"{app.base}{path}", json=body() if payload is None else payload, headers=sent, timeout=30
    )


def leave_after_the_first_chunk(app: KeystoneApp, token: str, payload: Any) -> bytes:
    """Start a stream and close the connection once the first bytes have come."""
    sent = {"Authorization": f"Bearer {token}"}
    with (
        httpx.Client(timeout=30) as client,
        client.stream("POST", f"{app.base}{ANTHROPIC}", json=payload, headers=sent) as response,
    ):
        for chunk in response.iter_raw():
            return chunk
    return b""


def give_up_on(app: KeystoneApp, token: str, payload: Any, *, after_s: float) -> None:
    """Send a request and hang up if no answer has come in `after_s` seconds."""
    with pytest.raises(httpx.ReadTimeout):
        httpx.post(
            f"{app.base}{ANTHROPIC}",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=after_s,
        )


async def sql(app: KeystoneApp, statement: str, **values: Any) -> list[Any]:
    """A statement run as the owner of the tables, and its rows."""
    engine = create_async_engine(app.database_url, poolclass=NullPool)
    try:
        async with engine.begin() as connection:
            result = await connection.execute(text(statement), values)
            return list(result.mappings()) if result.returns_rows else []
    finally:
        await engine.dispose()


async def ledger(app: KeystoneApp) -> list[Any]:
    return await sql(app, "SELECT * FROM spend_ledger WHERE kind = 'llm' ORDER BY ts, id")


async def ledger_after(app: KeystoneApp, count: int, seconds: float = 10) -> list[Any]:
    """The ledger once it holds `count` rows. A caller that left is booked a moment later."""
    deadline = time.monotonic() + seconds
    while True:
        rows = await ledger(app)
        if len(rows) >= count or time.monotonic() > deadline:
            return rows
        await asyncio.sleep(0.1)


def admin_get(app: KeystoneApp, idp: FakeIdp, path: str, user: str = "root") -> Any:
    response = httpx.get(
        f"{app.base}{API}{path}",
        headers={"Authorization": f"Bearer {idp.token_for(user)}"},
        timeout=15,
    )
    assert response.status_code == 200, response.text
    return response.json()


def get(app: KeystoneApp, path: str) -> httpx.Response:
    return httpx.get(f"{app.base}{path}", timeout=15)


def user_budget(user: str, limit: str) -> BudgetConfig:
    return BudgetConfig(
        tenant="acme", scope="user", scope_id=user, window="day", limit_usd=Decimal(limit)
    )


# -- the six the plan names


async def test_anthropic_nonstream_usage_recorded(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Any
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    answer = post(app, fake_idp.token_for("olivia"))

    assert answer.status_code == 200
    assert answer.json()["usage"] == {"input_tokens": 4, "output_tokens": 12}
    (row,) = await ledger(app)
    assert (row["tenant_id"], row["user_id"], row["agent_id"]) == ("acme", "olivia", "ops-agent")
    assert (row["model"], row["input_tokens"], row["output_tokens"]) == ("fake-model", 4, 12)
    assert row["cost_usd"] == ONE_CALL
    # The id the caller got back is the key of the row, so "what did that request cost" has an
    # answer.
    assert row["ref"] == answer.headers["x-keystone-request-id"]
    (seen,) = fake_llm.requests()
    assert (seen["path"], seen["key_ok"], seen["body"]) == ("/v1/messages", True, body())
    assert not {"authorization", "cookie"} & set(seen["header_names"])


async def test_anthropic_stream_usage_parsed(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Any
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    streamed = post(app, fake_idp.token_for("olivia"), payload=body(stream=True))

    assert streamed.status_code == 200
    assert streamed.headers["content-type"].startswith("text/event-stream")
    direct = fake_llm.post("/v1/messages", body(stream=True))
    # The events are the provider's own, byte for byte: the proxy only reads them as they pass.
    assert streamed.content == direct.content
    assert streamed.content.count(b"event: content_block_delta") == 12
    (row,) = await ledger(app)
    assert (row["input_tokens"], row["output_tokens"], row["cost_usd"]) == (4, 12, ONE_CALL)


async def test_openai_stream_include_usage_injected(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Any
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)
    token = fake_idp.token_for("olivia")

    streamed = post(app, token, OPENAI, body(stream=True))
    declined = post(
        app,
        token,
        OPENAI,
        body(stream=True, stream_options={"include_usage": False, "include_obfuscation": False}),
    )
    whole = post(app, token, OPENAI, body())

    first, second, third = (r["body"] for r in fake_llm.requests())
    assert first["stream_options"] == {"include_usage": True}
    assert first["messages"] == body()["messages"]  # the rest of the request is as it came
    # A caller that said no is overruled, because the cost is made from the count, and what else
    # it set is kept. An answer that is not a stream is not given the option.
    assert second["stream_options"] == {"include_usage": True, "include_obfuscation": False}
    assert "stream_options" not in third
    last = [
        json.loads(line[5:]) for line in streamed.text.splitlines() if line.startswith("data: {")
    ]
    assert last[-1]["choices"] == [] and last[-1]["usage"]["completion_tokens"] == 12
    assert streamed.status_code == declined.status_code == whole.status_code == 200
    rows = await ledger(app)
    assert [(r["input_tokens"], r["output_tokens"], r["cost_usd"]) for r in rows] == [
        (4, 12, ONE_CALL)
    ] * 3


async def test_budget_blocks_llm_call(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Any
) -> None:
    app = start(
        keystone_app_factory,
        fake_llm,
        fake_prices,
        settings={"budgets": [user_budget("olivia", "0.0004")]},
    )
    token = fake_idp.token_for("olivia")

    first = post(app, token)
    second = post(app, token)
    other = post(app, fake_idp.token_for("alice"))

    assert first.status_code == 200
    assert second.status_code == 402
    error = second.json()["error"]
    assert (error["type"], error["code"]) == ("keystone", "KS_BUDGET_EXCEEDED")
    assert (error["scope"], error["window"], error["limit_usd"]) == ("user", "day", 0.0004)
    # The first request spent what it used, not the estimate it was let in on.
    assert error["spent_usd"] == float(ONE_CALL)
    assert 0.0003 < error["estimate_usd"] < 0.0004 and error["resets_at"].endswith("T00:00:00Z")
    # The provider answered the first request and alice's, and never saw the one that was refused.
    assert other.status_code == 200
    assert len(fake_llm.requests()) == 2
    assert len(await ledger(app)) == 2
    spent = {b["scope_id"]: b["spent_usd"] for b in admin_get(app, fake_idp, "/budgets")}
    assert Decimal(spent["olivia"]) == ONE_CALL


async def test_unpriced_model_rejected(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Any
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    answer = post(app, fake_idp.token_for("olivia"), payload=body("mystery-model"))

    assert answer.status_code == 400
    error = answer.json()["error"]
    assert (error["type"], error["code"]) == ("keystone", "KS_MODEL_NOT_PRICED")
    assert "mystery-model" in error["message"] and "pricing file" in error["message"]
    assert fake_llm.requests() == []
    assert await ledger(app) == []


async def test_provider_key_never_returned(
    keystone_app_factory: Factory,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Any,
    log_buffer: io.StringIO,
) -> None:
    tracer, exporter = traced()
    app = start(keystone_app_factory, fake_llm, fake_prices, tracer=tracer)
    token = fake_idp.token_for("olivia")

    answers = [
        post(app, token),
        post(app, token, payload=body(stream=True)),
        post(app, token, OPENAI, body()),
        post(app, token, OPENAI, body(stream=True)),
        # Two providers that repeat the credential they were given, as some real ones do.
        post(app, token, ANTHROPIC, body("fake-error-echo-key")),
        post(app, token, OPENAI, body("fake-error-echo-key")),
        post(app, token, ANTHROPIC, body("fake-error-500")),
    ]

    assert [a.status_code for a in answers] == [200, 200, 200, 200, 401, 401, 500]
    # The provider got the key every time, so the test is not passing because it was never sent.
    assert all(r["key_ok"] for r in fake_llm.requests())
    assert len(fake_llm.requests()) == len(answers)
    assert "[redacted]" in answers[4].text and "[redacted]" in answers[5].text
    seen_by_the_caller = "\n".join(f"{a.headers}\n{a.text}" for a in answers)
    page = get(app, "/metrics").text
    upstreams = json.dumps(admin_get(app, fake_idp, "/upstreams"))
    observed = {
        "responses": seen_by_the_caller,
        "logs": log_buffer.getvalue(),
        "spans": dump(exporter.get_finished_spans()),
        "metrics": page,
        "admin": upstreams,
    }
    assert len(named(exporter.get_finished_spans(), "keystone.llm_call")) == len(answers)
    for where, text_ in observed.items():
        assert fake_llm.key not in text_, f"the provider key is in the {where}"
        assert f"Bearer {fake_llm.key}" not in text_, where
    # The stored copy is encrypted: the key is not in the row either.
    rows = await sql(app, "SELECT ciphertext FROM credentials")
    assert rows and all(fake_llm.key.encode() not in bytes(r["ciphertext"]) for r in rows)
    assert log_events(log_buffer, "llm_request")  # the logs were captured, and are not empty


# -- the rest of the behavior


async def test_an_unpriced_model_costs_nothing_when_the_owner_allows_it(
    keystone_app_factory: Factory,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Any,
    log_buffer: io.StringIO,
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices, llm={"allow_unpriced": True})

    answer = post(app, fake_idp.token_for("olivia"), payload=body("mystery-model"))

    assert answer.status_code == 200
    (row,) = await ledger(app)
    assert (row["model"], row["input_tokens"], row["output_tokens"]) == ("mystery-model", 4, 12)
    assert row["cost_usd"] == 0
    (warning,) = log_events(log_buffer, "llm_model_unpriced")
    assert warning["level"] == "warning" and warning["model"] == "mystery-model"
    page = get(app, "/metrics").text
    assert 'model="unpriced"' in page and "mystery-model" not in page


async def test_a_stream_without_its_final_count_is_booked_for_what_was_counted(
    keystone_app_factory: Factory,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Any,
    log_buffer: io.StringIO,
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)
    token = fake_idp.token_for("olivia")

    one = post(app, token, ANTHROPIC, body("fake-no-usage", stream=True))
    two = post(app, token, OPENAI, body("fake-no-usage", stream=True))

    # Both streams reach the caller whole. Anthropic's first event had the input and a placeholder
    # for the output, and OpenAI never said anything.
    assert one.status_code == two.status_code == 200
    assert one.content.endswith(b'data: {"type": "message_stop"}\n\n')
    assert two.content.endswith(b"data: [DONE]\n\n")
    rows = await ledger(app)
    assert [(r["input_tokens"], r["output_tokens"], r["cost_usd"]) for r in rows] == [
        (4, 1, Decimal("0.000027")),
        (None, None, Decimal(0)),
    ]
    warnings = log_events(log_buffer, "llm_usage_incomplete")
    assert [(w["reason"], w["level"]) for w in warnings] == [
        ("partial_usage", "warning"),
        ("no_usage", "warning"),
    ]


async def test_a_stream_that_breaks_is_booked_and_breaks_for_the_caller_too(
    keystone_app_factory: Factory,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Any,
    log_buffer: io.StringIO,
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    with pytest.raises(httpx.HTTPError):
        post(app, fake_idp.token_for("olivia"), payload=body("fake-cut", stream=True))

    (row,) = await ledger_after(app, 1)
    assert (row["input_tokens"], row["output_tokens"]) == (4, 1)
    assert row["cost_usd"] == Decimal("0.000027")
    assert [w["reason"] for w in log_events(log_buffer, "llm_usage_incomplete")] == ["cut"]


async def test_a_caller_that_leaves_a_stream_is_still_booked(
    keystone_app_factory: Factory,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Any,
    log_buffer: io.StringIO,
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    first = leave_after_the_first_chunk(
        app, fake_idp.token_for("olivia"), body("fake-slow", stream=True)
    )

    assert first
    (row,) = await ledger_after(app, 1)
    assert row["input_tokens"] == 4 and row["cost_usd"] > 0
    assert row["output_tokens"] < 12  # it left before the provider finished
    reasons = [w["reason"] for w in log_events(log_buffer, "llm_usage_incomplete")]
    assert reasons == ["client_gone"]
    # And the proxy is still serving: the lost connection did not leave anything held.
    assert post(app, fake_idp.token_for("olivia")).status_code == 200


async def test_a_caller_that_gives_up_on_a_whole_answer_is_still_charged_for_it(
    keystone_app_factory: Factory,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Any,
    log_buffer: io.StringIO,
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    # The fake takes half a second to answer; the caller hangs up after a fifth of one. Keystone
    # has already sent the request, so the provider finishes it and charges for it.
    give_up_on(app, fake_idp.token_for("olivia"), body("fake-slow"), after_s=0.2)

    (row,) = await ledger_after(app, 1)
    assert (row["input_tokens"], row["output_tokens"], row["cost_usd"]) == (4, 12, ONE_CALL)
    assert log_events(log_buffer, "llm_usage_incomplete") == []
    assert len(fake_llm.requests()) == 1


async def test_a_provider_error_goes_back_as_it_came_and_costs_nothing(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Any
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)
    token = fake_idp.token_for("olivia")

    limited = post(app, token, payload=body("fake-error-429"))
    broken = post(app, token, OPENAI, body("fake-error-500"))

    assert limited.status_code == 429 and limited.headers["retry-after"] == "7"
    assert limited.json()["error"]["type"] == "rate_limit_error"
    assert broken.status_code == 500 and "fell over" in broken.text
    assert await ledger(app) == []


async def test_a_request_can_be_linked_to_a_session_and_is_charged_to_it(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Any,
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    async with (
        mcp_client(app, user="olivia") as olivia,
        mcp_client(app, user="alice") as alice,
    ):
        await olivia.call_tool("keystone__whoami", {})
        await alice.call_tool("keystone__whoami", {})
        listed = admin_get(app, fake_idp, "/sessions")
        mine = next(s["session_id"] for s in listed if s["user_id"] == "olivia")
        theirs = next(s["session_id"] for s in listed if s["user_id"] == "alice")
        link = {"X-Keystone-Session": mine}

        linked = post(app, fake_idp.token_for("olivia"), headers=link)
        stolen = post(app, fake_idp.token_for("olivia"), headers={"X-Keystone-Session": theirs})
        unknown = post(
            app, fake_idp.token_for("olivia"), headers={"X-Keystone-Session": "no-such-session"}
        )

    assert linked.status_code == 200
    assert (stolen.status_code, stolen.json()["error"]["code"]) == (403, "KS_SESSION_MISMATCH")
    assert (unknown.status_code, unknown.json()["error"]["code"]) == (404, "KS_SESSION_NOT_FOUND")
    spent = {s["session_id"]: s["spent_usd"] for s in admin_get(app, fake_idp, "/sessions")}
    assert spent[mine] == pytest.approx(float(ONE_CALL)) and spent[theirs] == 0
    assert len(fake_llm.requests()) == 1 and len(await ledger(app)) == 1


async def test_model_spend_and_tool_spend_count_against_one_budget(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Any,
) -> None:
    priced_echo = UpstreamConfig(
        id="echo",
        tenant="acme",
        url=demo_upstreams.url("echo"),
        tools={"echo": ToolOverride(cost_per_call_usd=0.01)},
    )
    app = start(
        keystone_app_factory,
        fake_llm,
        fake_prices,
        settings={"upstreams": [priced_echo], "budgets": [user_budget("olivia", "0.0104")]},
    )
    token = fake_idp.token_for("olivia")

    async with mcp_client(app, user="olivia") as client:
        tool = await client.call_tool("echo__echo", {"payload": "x"})
    first = post(app, token)
    second = post(app, token)

    assert not tool.is_error and first.status_code == 200
    # A cent for the tool and then the cost of a model request leave too little for the estimate of
    # another: 0.010192 + 0.000321 is over 0.0104.
    assert second.status_code == 402
    assert second.json()["error"]["spent_usd"] == pytest.approx(0.010192)
    (budget,) = [b for b in admin_get(app, fake_idp, "/budgets") if b["scope_id"] == "olivia"]
    assert Decimal(budget["spent_usd"]) == Decimal("0.010192")
    kinds = await sql(
        app, "SELECT kind, count(*) AS n FROM spend_ledger GROUP BY kind ORDER BY kind"
    )
    assert [(k["kind"], k["n"]) for k in kinds] == [("llm", 1), ("tool", 1)]


async def test_the_provider_keys_are_in_the_vault_under_two_rows_nobody_lists(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Any
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices)

    rows = await sql(
        app,
        "SELECT id, tenant_id, transport, credential_mode, status FROM upstreams "
        "WHERE id LIKE 'llm\\_%' ORDER BY id",
    )
    stored = await sql(
        app, "SELECT upstream_id, user_id FROM credentials WHERE upstream_id LIKE 'llm\\_%'"
    )
    tools = await sql(app, "SELECT 1 FROM tools WHERE upstream_id LIKE 'llm\\_%'")

    assert [(r["id"], r["tenant_id"], r["credential_mode"], r["status"]) for r in rows] == [
        ("llm_anthropic", "acme", "static", "disabled"),
        ("llm_openai", "acme", "static", "disabled"),
    ]
    assert sorted((c["upstream_id"], c["user_id"]) for c in stored) == [
        ("llm_anthropic", None),
        ("llm_openai", None),
    ]
    assert tools == []  # nothing syncs them
    listed = [u["id"] for u in admin_get(app, fake_idp, "/upstreams")]
    assert not [i for i in listed if i.startswith("llm_")]
    # They are not probed either: the readiness check lists the real upstreams.
    ready = get(app, "/readyz").json()
    assert not [name for name in ready["upstreams"] if name.startswith("llm_")]


async def test_a_key_that_is_in_the_vault_stays_there_when_the_variable_goes_away(
    keystone_app_factory: Factory,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Any,
    log_buffer: io.StringIO,
) -> None:
    first = start(keystone_app_factory, fake_llm, fake_prices)
    assert post(first, fake_idp.token_for("olivia")).status_code == 200
    first.thread.stop()

    second = start(keystone_app_factory, fake_llm, fake_prices, environ={})
    answer = post(second, fake_idp.token_for("olivia"))

    assert answer.status_code == 200
    assert all(r["key_ok"] for r in fake_llm.requests())
    variables = {w["variable"] for w in log_events(log_buffer, "llm_key_variable_not_set")}
    assert variables == {"TEST_ANTHROPIC_KEY", "TEST_OPENAI_KEY"}


async def test_a_provider_with_no_key_anywhere_is_refused_before_a_request_is_sent(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Any
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices, environ={})

    answer = post(app, fake_idp.token_for("olivia"))

    assert answer.status_code == 503
    error = answer.json()["error"]
    assert error["code"] == "KS_PROVIDER_KEY_MISSING" and "TEST_ANTHROPIC_KEY" in error["message"]
    assert fake_llm.requests() == [] and await ledger(app) == []


async def test_a_caller_has_to_be_signed_in_and_of_the_tenant_that_owns_the_keys(
    keystone_app_factory: Factory, fake_idp: FakeIdp, fake_llm: FakeLlm, fake_prices: Any
) -> None:
    app = start(keystone_app_factory, fake_llm, fake_prices, globex=True)

    nobody = post(app, None)
    junk = post(app, "not.a.token")
    expired = post(app, fake_idp.token_for("olivia", exp_in=-60))
    globex = post(app, fake_idp.token_for("bob"))
    in_x_api_key = post(app, None, headers={"x-api-key": fake_idp.token_for("olivia")})

    assert [r.status_code for r in (nobody, junk, expired)] == [401, 401, 401]
    assert nobody.json()["error"]["code"] == "KS_UNAUTHORIZED"
    assert nobody.headers["www-authenticate"].startswith("Bearer resource_metadata=")
    assert (globex.status_code, globex.json()["error"]["code"]) == (403, "KS_DENIED")
    # The Anthropic SDK sends its key in x-api-key, and a Keystone token is its key here.
    assert in_x_api_key.status_code == 200
    assert len(fake_llm.requests()) == 1  # only the last one got as far as the provider


async def test_the_proxy_is_off_unless_the_config_turns_it_on(
    keystone_app_factory: Factory, fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory()

    answer = post(app, fake_idp.token_for("olivia"))

    assert answer.status_code == 404
    assert await sql(app, "SELECT 1 FROM upstreams WHERE id LIKE 'llm\\_%'") == []
