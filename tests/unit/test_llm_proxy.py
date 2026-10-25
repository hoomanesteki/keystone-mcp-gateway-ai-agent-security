"""KS-806 without services: the proxy in front of the fake model API, with the budgets in memory.

The provider is `examples/fake_llm`, reached through an in-process transport, and a request costs
what the table in `tests/fixtures/fake_llm.py` says: a prompt of four words and a reply of twelve
cost $0.000192. A provider that does something the fake cannot (breaks off a stream, redirects, does
not answer) is a mock transport.
"""

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import anyio
import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from starlette.datastructures import Headers
from structlog.testing import capture_logs

from examples.fake_llm.server import create_app as create_fake
from keystone.core.types import Principal
from keystone.gateway.sessions import InMemorySessionStore
from keystone.identity.jwt import AuthError, Forbidden, Reason
from keystone.metering.budgets import BudgetService, MemoryBudgets, MemoryCounters
from keystone.metering.ledger import LedgerEntry, MemoryLedger
from keystone.metering.llm_proxy import (
    PATHS,
    UPSTREAM_IDS,
    LlmProxy,
    Refusal,
    forward_headers,
    key_headers,
    mount_llm_proxy,
    parse_request,
    passed_headers,
    scrub,
    secrets_of,
    with_usage_reported,
)
from keystone.metering.pricing import ModelPrice, PriceList
from keystone.registry.naming import LLM_UPSTREAM_IDS
from keystone.settings import BudgetConfig, LlmProxySettings, Settings, TenantConfig
from keystone.telemetry.metrics import Metrics
from tests.fixtures.tracing import named, traced

pytestmark = pytest.mark.phase(8)

KEY = "fake-provider-key-unit-test-0123"
ANTHROPIC = "/llm/anthropic/v1/messages"
OPENAI = "/llm/openai/v1/chat/completions"
PROMPT = "hello there general kenobi"
USER = "olivia"
NOON = datetime(2026, 5, 4, 12, 0, tzinfo=UTC)
PRICES = PriceList(
    {
        "fake-model": ModelPrice(input_per_mtok=Decimal(3), output_per_mtok=Decimal(15)),
        "fake-model-cached": ModelPrice(
            input_per_mtok=Decimal(3),
            output_per_mtok=Decimal(15),
            cache_read_per_mtok=Decimal("0.30"),
            cache_write_per_mtok=Decimal("3.75"),
        ),
        "fake-*": ModelPrice(input_per_mtok=Decimal(3), output_per_mtok=Decimal(15)),
    }
)


def body(model: str = "fake-model", **extra: Any) -> dict[str, Any]:
    return {
        "model": model,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": PROMPT}],
        **extra,
    }


class Tokens:
    """The bearer token names the user. `bob` is of the other tenant; two tokens fail."""

    async def principal(self, headers: Headers) -> Principal:
        scheme, _, token = headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthError(Reason.NO_CREDENTIALS)
        if token == "expired":
            raise AuthError(Reason.EXPIRED)
        if token == "banned":
            raise Forbidden(Reason.UNKNOWN_AGENT)
        tenant = "globex" if token == "bob" else "acme"
        return Principal(tenant_id=tenant, user_id=token, agent_id="ops-agent")


class Keys:
    """The vault, for the two providers."""

    def __init__(self, headers: Mapping[str, str] | None) -> None:
        self.headers = {} if headers is None else dict(headers)
        self.asked: list[tuple[str, str]] = []

    async def service_headers(self, tenant_id: str, upstream_id: str) -> dict[str, SecretStr]:
        self.asked.append((tenant_id, upstream_id))
        return {name: SecretStr(value) for name, value in self.headers.items()}


class BrokenKeys:
    async def service_headers(self, tenant_id: str, upstream_id: str) -> dict[str, SecretStr]:
        raise RuntimeError(f"the vault is down, {KEY}")


class BrokenBudgets:
    async def check(self, principal: Principal, cost: float | Decimal) -> None:
        raise RuntimeError("redis is down")

    async def record(self, entry: LedgerEntry) -> bool:
        return True


class Chunks(httpx2.AsyncByteStream):
    """A body that arrives in the pieces it is given, and fails after them if told to, as a
    connection that is lost does."""

    def __init__(self, chunks: list[bytes], *, then_fail: bool = False) -> None:
        self.chunks = chunks
        self.then_fail = then_fail

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk
        if self.then_fail:
            raise httpx2.ReadError("the connection was lost")


FIRST_EVENT = (
    b'event: message_start\ndata: {"type":"message_start","message":{"model":"fake-model",'
    b'"usage":{"input_tokens":4,"output_tokens":1}}}\n\n'
)
PING = b'event: ping\ndata: {"type":"ping"}\n\n'


def event_stream(*chunks: bytes, then_fail: bool = False) -> httpx2.MockTransport:
    def answer(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=Chunks(list(chunks), then_fail=then_fail),
        )

    return httpx2.MockTransport(answer)


@dataclass
class Rig:
    web: TestClient
    fake: FastAPI
    ledger: MemoryLedger
    counters: MemoryCounters
    sessions: InMemorySessionStore
    metrics: Metrics
    keys: Keys
    spans: Any

    def provider_saw(self) -> list[dict[str, Any]]:
        with TestClient(self.fake) as view:
            found: list[dict[str, Any]] = view.get("/_state").json()["requests"]
        return found

    def post(self, path: str, payload: Any = None, token: str | None = USER, **options: Any) -> Any:
        headers = dict(options.pop("headers", {}))
        if token is not None:
            headers.setdefault("authorization", f"Bearer {token}")
        if payload is not None:
            options.setdefault("json", payload)
        return self.web.post(path, headers=headers, **options)


def provider_transport(fake: FastAPI) -> httpx2.AsyncBaseTransport:
    return httpx2.ASGITransport(app=fake)


def build(
    *,
    transport: httpx2.AsyncBaseTransport | None = None,
    budgets: list[BudgetConfig] | None = None,
    keys: Mapping[str, str] | None = None,
    llm: Mapping[str, Any] | None = None,
    vault: Any = None,
    spending: Any = None,
    prices: PriceList = PRICES,
) -> Rig:
    fake = create_fake(KEY)
    proxy_options: dict[str, Any] = {
        "enabled": True,
        "tenant": "acme",
        "pricing_file": "unused.yaml",
        "anthropic": {"base_url": "http://provider.test", "api_key_env": "ANTHROPIC_KEY"},
        "openai": {"base_url": "http://provider.test", "api_key_env": "OPENAI_KEY"},
    }
    proxy_options.update(llm or {})
    settings = Settings(
        env="test",
        oidc_issuer="http://idp.test/realms/keystone",
        tenants=[TenantConfig(id="acme", name="Acme"), TenantConfig(id="globex", name="Globex")],
        llm_proxy=LlmProxySettings(**proxy_options),
    )
    ledger, counters = MemoryLedger(), MemoryCounters()
    metrics = Metrics(tenants=["acme", "globex"])
    service = BudgetService(MemoryBudgets(), ledger, counters, clock=lambda: NOON, metrics=metrics)
    asyncio.run(service.start(budgets or [], ["acme", "globex"]))
    sessions = InMemorySessionStore()
    tracer, spans = traced()
    vault_ = vault or Keys(keys if keys is not None else key_headers("anthropic", KEY))
    http = httpx2.AsyncClient(transport=transport or provider_transport(fake))
    proxy = LlmProxy(
        settings,
        authenticator=Tokens(),
        vault=vault_,
        budgets=spending or service,
        sessions=sessions,
        prices=prices,
        metrics=metrics,
        tracer=tracer,
        now=lambda: NOON,
        client=http,
    )
    app = FastAPI()
    mount_llm_proxy(app, proxy)
    web = TestClient(app, raise_server_exceptions=False)
    return Rig(web, fake, ledger, counters, sessions, metrics, vault_, spans)


@pytest.fixture
def rig() -> Rig:
    # Both providers use the same stored key here, as the fake takes the one key in either place.
    return build(keys=None)


def anthropic_rig(**options: Any) -> Rig:
    return build(**options)


def openai_rig(**options: Any) -> Rig:
    return build(keys=key_headers("openai", KEY), **options)


def only_entry(rig: Rig) -> LedgerEntry:
    assert len(rig.ledger.entries) == 1, rig.ledger.entries
    return rig.ledger.entries[0]


# -- reading a request


def raw(payload: Any) -> bytes:
    return json.dumps(payload).encode()


def test_a_request_needs_a_json_object_with_the_name_of_a_model() -> None:
    for text, why in [
        (b"not json", "valid JSON"),
        (b"[1, 2]", "JSON object"),
        (raw({"messages": []}), "model"),
        (raw({"model": 7}), "model"),
        (raw({"model": "  "}), "model"),
        (raw({"model": "m" * 201}), "model"),
        (raw({"model": "m", "stream": "yes"}), "stream"),
        (b"[" * 100_000, "valid JSON"),
    ]:
        with pytest.raises(Refusal) as refused:
            parse_request("anthropic", text, 4096)
        assert refused.value.status == 400 and why in refused.value.message


def test_the_output_a_request_asks_for_is_what_its_budget_check_assumes() -> None:
    asked = parse_request("anthropic", raw(body(max_tokens=300)), 4096)
    unsaid = parse_request("openai", raw({"model": "m"}), 4096)
    many = parse_request("openai", raw({"model": "m", "max_tokens": 50, "n": 3}), 4096)
    newer = parse_request(
        "openai", raw({"model": "m", "max_tokens": 50, "max_completion_tokens": 70}), 4096
    )
    silly = parse_request("openai", raw({"model": "m", "max_tokens": 10**12, "n": 10**6}), 4096)

    assert asked.max_output == 300 and not asked.stream
    assert unsaid.max_output == 4096
    assert many.max_output == 150
    assert newer.max_output == 70
    # A number that large only has to be larger than any budget, and not break the sums.
    assert silly.max_output == 10_000_000


def test_usage_is_asked_of_an_openai_stream_without_changing_the_rest() -> None:
    plain = {"model": "m", "stream": True, "messages": [{"role": "user", "content": "é"}]}

    forced = json.loads(with_usage_reported(plain) or b"")
    declined = json.loads(
        with_usage_reported({**plain, "stream_options": {"include_usage": False, "other": 1}})
        or b""
    )

    assert forced == {**plain, "stream_options": {"include_usage": True}}
    assert declined["stream_options"] == {"include_usage": True, "other": 1}
    assert with_usage_reported({**plain, "stream_options": {"include_usage": True}}) is None
    assert json.loads(with_usage_reported({**plain, "stream_options": None}) or b"")[
        "stream_options"
    ] == {"include_usage": True}


def test_only_a_short_list_of_the_callers_headers_goes_to_the_provider() -> None:
    sent = forward_headers(
        {
            "authorization": "Bearer the-callers-token",
            "x-api-key": "the-callers-token",
            "cookie": "session=1",
            "x-keystone-session": "abc",
            "x-forwarded-for": "10.0.0.1",
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "tools-2024-04-04",
            "accept": "text/event-stream",
            "accept-encoding": "gzip, br",
            "openai-organization": "org-someone-elses",
        }
    )

    assert sent == {
        "content-type": "application/json",
        "accept-encoding": "identity",
        "user-agent": sent["user-agent"],
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "tools-2024-04-04",
        "accept": "text/event-stream",
    }
    assert sent["user-agent"].startswith("keystone/")
    # A value that is not printable ASCII, or is very long, is dropped and not sent on.
    assert "anthropic-version" not in forward_headers({"anthropic-version": "2023\x00"})
    assert "accept" not in forward_headers({"accept": "x" * 300})


def test_the_provider_key_is_taken_out_of_what_comes_back() -> None:
    headers = key_headers("openai", KEY)
    secrets = secrets_of(headers)

    assert secrets == (f"Bearer {KEY}", KEY)
    assert scrub(f"wrong key: {KEY}, Bearer {KEY}".encode(), secrets) == (
        b"wrong key: [redacted], [redacted]"
    )
    assert secrets_of({"x-api-key": "short"}) == ()  # too short to match safely in a log
    kept = passed_headers(
        httpx2.Headers(
            {
                "content-type": "application/json",
                "retry-after": "7",
                "request-id": f"req-{KEY}",
                "anthropic-ratelimit-tokens-remaining": "100",
                "set-cookie": "a=b",
                "location": "http://elsewhere",
            }
        ),
        secrets,
    )
    assert kept == {
        "content-type": "application/json",
        "retry-after": "7",
        "request-id": "req-[redacted]",
    }


# -- one request


def test_an_anthropic_request_is_sent_with_the_providers_key_and_booked(rig: Rig) -> None:
    answer = rig.post(ANTHROPIC, body(), headers={"anthropic-version": "2023-06-01"})

    assert answer.status_code == 200
    assert answer.json()["usage"] == {"input_tokens": 4, "output_tokens": 12}
    entry = only_entry(rig)
    assert (entry.kind, entry.tenant_id, entry.user_id, entry.agent_id) == (
        "llm",
        "acme",
        "olivia",
        "ops-agent",
    )
    assert (entry.model, entry.input_tokens, entry.output_tokens) == ("fake-model", 4, 12)
    assert entry.cost_usd == Decimal("0.000192")
    assert entry.ref == answer.headers["x-keystone-request-id"] and entry.ts == NOON
    (seen,) = rig.provider_saw()
    assert (seen["path"], seen["key_received"], seen["key_ok"]) == ("/v1/messages", True, True)
    assert seen["anthropic_version"] == "2023-06-01" and seen["accept_encoding"] == "identity"
    # Nothing of the caller's reached the provider but the body: its token was replaced by the key.
    assert not {"authorization", "cookie", "x-keystone-session"} & set(seen["header_names"])
    assert seen["body"] == body()


def test_the_token_can_come_in_x_api_key_where_the_anthropic_sdk_puts_its_key(rig: Rig) -> None:
    answer = rig.post(ANTHROPIC, body(), token=None, headers={"x-api-key": "olivia"})

    assert answer.status_code == 200
    assert only_entry(rig).user_id == "olivia"
    # The caller's token does not go on: the key the provider got is the vault's.
    assert rig.provider_saw()[0]["key_ok"] is True


def test_an_openai_request_is_sent_with_a_bearer_key() -> None:
    rig = openai_rig()

    answer = rig.post(OPENAI, body())

    assert answer.status_code == 200
    assert answer.json()["usage"]["prompt_tokens"] == 4
    entry = only_entry(rig)
    assert (entry.input_tokens, entry.output_tokens, entry.cost_usd) == (4, 12, Decimal("0.000192"))
    (seen,) = rig.provider_saw()
    assert (seen["path"], seen["key_ok"]) == ("/v1/chat/completions", True)
    assert "stream_options" not in seen["body"]  # asked for only when it is a stream


def test_cached_tokens_are_priced_apart(rig: Rig) -> None:
    rig.post(ANTHROPIC, body("fake-model-cached"))
    openai = openai_rig()
    openai.post(OPENAI, body("fake-model-cached"))

    one, two = only_entry(rig), only_entry(openai)
    # 4 fresh and 5 cached read and 2 cached written at three prices, and 12 out.
    assert one.input_tokens == 11 and one.output_tokens == 12
    assert one.cost_usd == Decimal("0.000201")
    assert two.input_tokens == 9 and two.cost_usd == Decimal("0.0001935")


@pytest.mark.parametrize(
    ("headers", "token", "status", "code"),
    [
        ({}, None, 401, "KS_UNAUTHORIZED"),
        ({}, "expired", 401, "KS_UNAUTHORIZED"),
        ({}, "banned", 403, "KS_FORBIDDEN"),
        ({}, "bob", 403, "KS_DENIED"),
    ],
)
def test_a_request_that_is_not_let_in_is_refused_with_the_status_of_mcp(
    rig: Rig, headers: dict[str, str], token: str | None, status: int, code: str
) -> None:
    answer = rig.post(ANTHROPIC, body(), token=token, headers=headers)

    assert answer.status_code == status
    error = answer.json()["error"]
    assert error["type"] == "keystone" and error["code"] == code and error["message"]
    assert rig.provider_saw() == [] and rig.ledger.entries == []
    if status == 401:
        assert answer.headers["www-authenticate"].startswith("Bearer resource_metadata=")


@pytest.mark.parametrize(
    ("options", "status", "word"),
    [
        ({"content": b"{not json"}, 400, "JSON"),
        ({"json": [1]}, 400, "object"),
        ({"json": {"messages": []}}, 400, "model"),
        ({"json": body(stream="yes")}, 400, "stream"),
        ({"json": body(), "headers": {"content-encoding": "gzip"}}, 415, "content-encoding"),
        ({"content": b"x" * 5000}, 413, "limit"),
    ],
)
def test_a_bad_request_is_refused_before_anything_is_sent(
    options: dict[str, Any], status: int, word: str
) -> None:
    rig = build(llm={"max_body_bytes": 4096})

    answer = rig.post(ANTHROPIC, **options)

    assert answer.status_code == status and word in answer.json()["error"]["message"]
    assert rig.provider_saw() == [] and rig.ledger.entries == []


def test_a_model_with_no_price_is_refused(rig: Rig) -> None:
    answer = rig.post(ANTHROPIC, body("mystery-model"))

    assert answer.status_code == 400
    error = answer.json()["error"]
    assert error["code"] == "KS_MODEL_NOT_PRICED" and "mystery-model" in error["message"]
    assert rig.provider_saw() == [] and rig.ledger.entries == []


def test_an_unpriced_model_costs_nothing_when_the_owner_allows_it() -> None:
    rig = build(llm={"allow_unpriced": True}, prices=PriceList({}))

    with capture_logs() as logs:
        answer = rig.post(ANTHROPIC, body("mystery-model"))

    assert answer.status_code == 200
    entry = only_entry(rig)
    assert (entry.cost_usd, entry.input_tokens, entry.output_tokens) == (Decimal(0), 4, 12)
    warned = [e for e in logs if e["event"] == "llm_model_unpriced"]
    assert warned and warned[0]["log_level"] == "warning" and warned[0]["model"] == "mystery-model"
    # Its tokens are counted under a label of ours and not the name the caller chose.
    page = rig.metrics.render().decode()
    assert 'model="unpriced"' in page and "mystery-model" not in page


def test_a_request_that_would_pass_a_budget_never_reaches_the_provider() -> None:
    limit = BudgetConfig(
        tenant="acme", scope="user", scope_id="olivia", window="day", limit_usd=Decimal("0.0004")
    )
    rig = build(budgets=[limit])

    first = rig.post(ANTHROPIC, body())
    second = rig.post(ANTHROPIC, body())
    other = rig.post(ANTHROPIC, body(), token="alice")

    assert first.status_code == 200
    assert second.status_code == 402
    error = second.json()["error"]
    assert error["code"] == "KS_BUDGET_EXCEEDED" and error["type"] == "keystone"
    assert (error["scope"], error["window"], error["limit_usd"]) == ("user", "day", 0.0004)
    assert error["spent_usd"] == 0.000192 and 0.0003 < error["estimate_usd"] < 0.0004
    assert error["resets_at"] == "2026-05-05T00:00:00Z"
    assert "$0.0004" in error["message"] and "olivia" not in error["message"]
    # The provider answered one request for olivia and one for alice, and nothing for the refused.
    assert [r["path"] for r in rig.provider_saw()] == ["/v1/messages", "/v1/messages"]
    assert other.status_code == 200
    assert len(rig.ledger.entries) == 2


def test_the_estimate_is_the_body_at_four_bytes_a_token_and_the_output_asked_for() -> None:
    # 16 tokens of output at $15 a million is $0.00024, and the body adds the input.
    sent = raw(body())
    estimate = Decimal((len(sent) + 3) // 4) * 3 / 1_000_000 + Decimal(16) * 15 / 1_000_000
    just_over = BudgetConfig(
        tenant="acme",
        scope="user",
        scope_id="olivia",
        window="day",
        limit_usd=(estimate - Decimal("0.000000001")).quantize(Decimal("0.000000001")),
    )
    just_enough = just_over.model_copy(update={"limit_usd": estimate})

    refused = build(budgets=[just_over]).post(ANTHROPIC, content=sent)
    allowed = build(budgets=[just_enough]).post(ANTHROPIC, content=sent)

    assert refused.status_code == 402 and allowed.status_code == 200
    assert refused.json()["error"]["estimate_usd"] == pytest.approx(float(estimate))


def test_a_budget_that_cannot_be_read_stops_the_request() -> None:
    rig = build(spending=BrokenBudgets())

    with capture_logs() as logs:
        answer = rig.post(ANTHROPIC, body())

    assert answer.status_code == 503
    assert answer.json()["error"]["code"] == "KS_UNAVAILABLE"
    assert rig.provider_saw() == []
    assert any(e["event"] == "llm_budget_check_failed" for e in logs)
    assert "redis is down" not in json.dumps(logs)


def test_a_request_can_be_linked_to_a_session_of_the_same_caller() -> None:
    rig = build()
    olivia = Principal(tenant_id="acme", user_id="olivia", agent_id="ops-agent")
    other = Principal(tenant_id="acme", user_id="alice", agent_id="ops-agent")
    asyncio.run(rig.sessions.create("mine", olivia))
    asyncio.run(rig.sessions.create("theirs", other))

    linked = rig.post(ANTHROPIC, body(), headers={"X-Keystone-Session": "mine"})
    taken = rig.post(ANTHROPIC, body(), headers={"X-Keystone-Session": "theirs"})
    unknown = rig.post(ANTHROPIC, body(), headers={"X-Keystone-Session": "nobody"})
    odd = rig.post(ANTHROPIC, body(), headers={"X-Keystone-Session": "a b\tc"})

    assert linked.status_code == 200
    assert (taken.status_code, taken.json()["error"]["code"]) == (403, "KS_SESSION_MISMATCH")
    assert (unknown.status_code, unknown.json()["error"]["code"]) == (404, "KS_SESSION_NOT_FOUND")
    assert odd.status_code == 404
    mine = asyncio.run(rig.sessions.get("mine"))
    theirs = asyncio.run(rig.sessions.get("theirs"))
    assert mine is not None and theirs is not None
    assert mine.spent_usd == pytest.approx(0.000192) and theirs.spent_usd == 0
    assert len(rig.ledger.entries) == 1 and len(rig.provider_saw()) == 1


def test_a_provider_without_a_key_is_not_sent_a_request() -> None:
    rig = build(keys={})

    with capture_logs() as logs:
        answer = rig.post(ANTHROPIC, body())

    assert answer.status_code == 503
    error = answer.json()["error"]
    assert error["code"] == "KS_PROVIDER_KEY_MISSING" and "ANTHROPIC_KEY" in error["message"]
    assert rig.provider_saw() == []
    assert any(e["event"] == "llm_key_missing" for e in logs)


def test_a_provider_that_needs_no_key_is_sent_the_request_without_one() -> None:
    rig = build(
        keys={},
        llm={"anthropic": {"base_url": "http://provider.test", "api_key_env": None}},
    )

    answer = rig.post(ANTHROPIC, body())

    # The fake wants a key, so it refuses; the point is that Keystone did not stop it first.
    assert answer.status_code == 401
    assert rig.provider_saw()[0]["key_received"] is False


def test_a_vault_that_fails_is_a_503_that_does_not_repeat_the_failure() -> None:
    rig = build(vault=BrokenKeys())

    answer = rig.post(ANTHROPIC, body())

    assert answer.status_code == 503 and KEY not in answer.text
    assert "vault is down" not in answer.text


# -- what the provider says back


def test_a_provider_error_goes_back_with_its_status_and_without_the_key(rig: Rig) -> None:
    limited = rig.post(ANTHROPIC, body("fake-error-429"))
    broken = rig.post(ANTHROPIC, body("fake-error-500"))
    echoing = rig.post(ANTHROPIC, body("fake-error-echo-key"))

    assert limited.status_code == 429 and limited.headers["retry-after"] == "7"
    assert limited.json()["error"]["type"] == "rate_limit_error"
    assert broken.status_code == 500
    assert echoing.status_code == 401
    assert KEY not in echoing.text and "[redacted]" in echoing.text
    assert rig.ledger.entries == []  # a request the provider refused costs nothing


def test_a_provider_that_cannot_be_reached_or_is_too_slow_is_a_502_and_a_504() -> None:
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError(f"cannot connect to {request.url} with {KEY}")

    def stall(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ReadTimeout(f"timed out, {KEY}")

    down = build(transport=httpx2.MockTransport(refuse)).post(ANTHROPIC, body())
    slow = build(transport=httpx2.MockTransport(stall)).post(ANTHROPIC, body())

    assert (down.status_code, down.json()["error"]["code"]) == (502, "KS_UPSTREAM_ERROR")
    assert (slow.status_code, slow.json()["error"]["code"]) == (504, "KS_UPSTREAM_TIMEOUT")
    assert KEY not in down.text + slow.text and "provider.test" not in down.text


def test_a_redirect_is_not_followed_and_is_not_passed_on() -> None:
    def moved(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(302, headers={"location": "http://elsewhere.test/steal"})

    rig = build(transport=httpx2.MockTransport(moved))

    answer = rig.post(ANTHROPIC, body())

    assert answer.status_code == 502 and "elsewhere" not in answer.text
    assert "location" not in answer.headers


# -- streams


def test_a_stream_goes_through_unchanged_and_is_booked_when_it_ends(rig: Rig) -> None:
    with TestClient(rig.fake) as direct:
        expected = direct.post("/v1/messages", json=body(stream=True), headers={"x-api-key": KEY})
    rig.provider_saw()

    answer = rig.post(ANTHROPIC, body(stream=True))

    assert answer.status_code == 200
    assert answer.headers["content-type"].startswith("text/event-stream")
    assert answer.content == expected.content
    entry = only_entry(rig)
    assert (entry.input_tokens, entry.output_tokens, entry.cost_usd) == (4, 12, Decimal("0.000192"))


def test_an_openai_stream_is_told_to_report_its_usage_and_still_passes_unchanged() -> None:
    rig = openai_rig()
    asked = body(stream=True, stream_options={"include_usage": True})
    with TestClient(rig.fake) as direct:
        expected = direct.post(
            "/v1/chat/completions", json=asked, headers={"authorization": f"Bearer {KEY}"}
        )
    rig.provider_saw()

    answer = rig.post(OPENAI, body(stream=True))

    assert answer.content == expected.content
    assert rig.provider_saw()[-1]["body"]["stream_options"] == {"include_usage": True}
    entry = only_entry(rig)
    assert (entry.input_tokens, entry.output_tokens, entry.cost_usd) == (4, 12, Decimal("0.000192"))


def test_a_stream_that_never_gives_its_final_count_is_booked_for_what_was_counted(
    rig: Rig,
) -> None:
    with capture_logs() as logs:
        answer = rig.post(ANTHROPIC, body("fake-no-usage", stream=True))

    assert answer.status_code == 200
    # The input came in the first event, and the output is the placeholder one of it.
    entry = only_entry(rig)
    assert (entry.input_tokens, entry.output_tokens) == (4, 1)
    assert entry.cost_usd == Decimal("0.000027")
    warned = [e for e in logs if e["event"] == "llm_usage_incomplete"]
    assert [(w["reason"], w["log_level"]) for w in warned] == [("partial_usage", "warning")]


def test_a_stream_with_no_usage_at_all_is_booked_at_nothing_and_says_so() -> None:
    rig = openai_rig()

    with capture_logs() as logs:
        answer = rig.post(OPENAI, body("fake-no-usage", stream=True))

    assert answer.status_code == 200
    entry = only_entry(rig)
    assert (entry.input_tokens, entry.output_tokens, entry.cost_usd) == (None, None, Decimal(0))
    warned = [e for e in logs if e["event"] == "llm_usage_incomplete"]
    assert [w["reason"] for w in warned] == ["no_usage"]
    assert warned[0]["counted"] is False


def test_a_stream_that_breaks_is_booked_for_what_came_and_the_caller_sees_it_break() -> None:
    rig = build(transport=event_stream(FIRST_EVENT, PING, then_fail=True))

    with capture_logs() as logs:
        answer = rig.post(ANTHROPIC, body(stream=True))

    # The server failed after the answer had begun: the status was sent, and the body is cut.
    assert answer.status_code in (200, 500)
    entry = only_entry(rig)
    assert (entry.input_tokens, entry.output_tokens, entry.cost_usd) == (4, 1, Decimal("0.000027"))
    assert [w["reason"] for w in logs if w["event"] == "llm_usage_incomplete"] == ["cut"]
    spans = named(rig.spans.get_finished_spans(), "keystone.llm_call")
    assert [dict(s.attributes or {}).get("keystone.llm.ended") for s in spans] == ["cut"]


# -- a caller that leaves


async def hang_up(rig: Rig, path: str, payload: dict[str, Any], *, after: int) -> None:
    """Send the request to the app by hand and let the connection fail once `after` messages of
    the answer have been sent, as an ASGI server does when the client has gone."""
    sent_body = json.dumps(payload).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [
            (b"authorization", b"Bearer olivia"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(sent_body)).encode()),
        ],
        "server": ("keystone.test", 80),
        "client": ("127.0.0.1", 50000),
    }
    asked = False
    sent = 0

    async def receive() -> dict[str, Any]:
        nonlocal asked
        if not asked:
            asked = True
            return {"type": "http.request", "body": sent_body, "more_body": False}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal sent
        sent += 1
        if sent > after:
            raise OSError("the client has gone")

    with contextlib.suppress(Exception):
        await rig.web.app(scope, receive, send)  # type: ignore[arg-type]


def test_a_caller_that_hangs_up_on_a_whole_answer_is_still_charged_for_it() -> None:
    rig = build()

    with capture_logs() as logs:
        asyncio.run(hang_up(rig, ANTHROPIC, body(), after=0))

    # The provider had finished the answer, so Keystone read it to the end to learn what it cost.
    entry = only_entry(rig)
    assert (entry.input_tokens, entry.output_tokens, entry.cost_usd) == (4, 12, Decimal("0.000192"))
    assert not [e for e in logs if e["event"] == "llm_usage_incomplete"]
    assert [e["ended"] for e in logs if e["event"] == "llm_request"] == ["complete"]


def test_a_caller_that_hangs_up_on_a_stream_is_charged_for_what_was_counted() -> None:
    rig = build(transport=event_stream(FIRST_EVENT, PING, PING))

    with capture_logs() as logs:
        # The status and the headers go out, and the first event does not.
        asyncio.run(hang_up(rig, ANTHROPIC, body(stream=True), after=2))

    entry = only_entry(rig)
    # message_start gave the input and a placeholder of one for the output.
    assert (entry.input_tokens, entry.output_tokens) == (4, 1)
    assert entry.cost_usd == Decimal("0.000027")
    assert [(e["reason"], e["counted"]) for e in logs if e["event"] == "llm_usage_incomplete"] == [
        ("client_gone", True)
    ]


def test_a_caller_that_hangs_up_before_a_stream_begins_costs_what_is_known_which_is_nothing() -> (
    None
):
    rig = build()

    with capture_logs() as logs:
        asyncio.run(hang_up(rig, ANTHROPIC, body(stream=True), after=0))

    entry = only_entry(rig)
    assert (entry.input_tokens, entry.output_tokens, entry.cost_usd) == (None, None, Decimal(0))
    assert [e["reason"] for e in logs if e["event"] == "llm_usage_incomplete"] == ["client_gone"]
    # The provider's connection was closed, and the span ended.
    assert len(named(rig.spans.get_finished_spans(), "keystone.llm_call")) == 1


def test_a_provider_connection_pool_that_is_full_is_a_503_to_try_again() -> None:
    def full(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.PoolTimeout("no free connection")

    rig = build(transport=httpx2.MockTransport(full))

    answer = rig.post(ANTHROPIC, body())

    assert answer.status_code == 503 and answer.headers["retry-after"] == "1"
    assert answer.json()["error"]["code"] == "KS_UNAVAILABLE"
    assert rig.ledger.entries == []


# -- what is recorded about a request


def test_the_span_of_a_request_has_the_genai_attributes_and_no_secret(rig: Rig) -> None:
    rig.post(ANTHROPIC, body(), headers={"traceparent": "00-" + "ab" * 16 + "-" + "cd" * 8 + "-01"})

    (span,) = named(rig.spans.get_finished_spans(), "keystone.llm_call")
    attributes = dict(span.attributes or {})
    assert attributes["gen_ai.system"] == "anthropic"
    assert attributes["gen_ai.request.model"] == "fake-model"
    assert attributes["gen_ai.usage.input_tokens"] == 4
    assert attributes["gen_ai.usage.output_tokens"] == 12
    assert attributes["keystone.cost_usd"] == pytest.approx(0.000192)
    assert (attributes["keystone.tenant"], attributes["keystone.agent"]) == ("acme", "ops-agent")
    assert attributes["keystone.outcome"] == "ok" and attributes["http.response.status_code"] == 200
    assert "olivia" not in span.to_json() and KEY not in span.to_json()
    assert attributes["keystone.user_hash"] and len(str(attributes["keystone.user_hash"])) == 12
    # It continues the caller's trace.
    assert span.context is not None and format(span.context.trace_id, "032x") == "ab" * 16
    assert span.parent is not None and format(span.parent.span_id, "016x") == "cd" * 8


def test_a_refused_request_leaves_a_span_that_says_why() -> None:
    rig = build()

    rig.post(ANTHROPIC, body("mystery-model"))
    rig.post(ANTHROPIC, body("fake-error-500"))

    spans = named(rig.spans.get_finished_spans(), "keystone.llm_call")
    seen = [dict(s.attributes or {}) for s in spans]
    assert [(a["keystone.outcome"], a.get("keystone.reject_code")) for a in seen[:1]] == [
        ("rejected", "KS_MODEL_NOT_PRICED")
    ]
    assert seen[1]["keystone.outcome"] == "error" and seen[1]["http.response.status_code"] == 500
    assert all(a["gen_ai.system"] == "anthropic" for a in seen)


def test_tokens_are_counted_by_the_name_of_the_price_that_applied(rig: Rig) -> None:
    rig.post(ANTHROPIC, body("fake-model-cached"))
    rig.post(ANTHROPIC, body("fake-anything-else"))

    page = rig.metrics.render().decode()

    def series(direction: str, model: str, count: str) -> str:
        return (
            f'keystone_llm_tokens_total{{direction="{direction}",model="{model}",tenant="acme"}} '
            f"{count}"
        )

    for line in (
        series("input", "fake-model-cached", "4.0"),
        series("cache_read", "fake-model-cached", "5.0"),
        series("cache_write", "fake-model-cached", "2.0"),
        series("output", "fake-*", "12.0"),
    ):
        assert line in page, line
    # The model a caller names is theirs to choose, so it is not a label.
    assert "fake-anything-else" not in page


def test_the_log_line_of_a_request_has_what_it_cost_and_nothing_of_the_caller(rig: Rig) -> None:
    with capture_logs() as logs:
        answer = rig.post(ANTHROPIC, body())

    (line,) = [e for e in logs if e["event"] == "llm_request"]
    assert line["request_id"] == answer.headers["x-keystone-request-id"]
    assert (line["provider"], line["model"], line["status"], line["ended"]) == (
        "anthropic",
        "fake-model",
        200,
        "complete",
    )
    assert (line["input_tokens"], line["output_tokens"], line["cost_usd"]) == (4, 12, "0.000192")
    assert "olivia" not in json.dumps(logs) and KEY not in json.dumps(logs)


def test_a_booking_that_fails_is_logged_and_the_answer_still_goes_out() -> None:
    class Failing(BrokenBudgets):
        async def check(self, principal: Principal, cost: float | Decimal) -> None:
            return None

        async def record(self, entry: LedgerEntry) -> bool:
            raise RuntimeError("postgres is down")

    rig = build(spending=Failing())

    with capture_logs() as logs:
        answer = rig.post(ANTHROPIC, body())

    assert answer.status_code == 200
    failed = [e for e in logs if e["event"] == "llm_booking_failed"]
    assert failed and failed[0]["log_level"] == "error" and failed[0]["model"] == "fake-model"
    spans = named(rig.spans.get_finished_spans(), "keystone.llm_call")
    assert len(spans) == 1  # the span still ends


def test_the_two_routes_are_all_there_is() -> None:
    rig = build()

    assert rig.web.get(ANTHROPIC).status_code == 405
    assert rig.web.post("/llm/anthropic/v1/other", json=body()).status_code == 404
    assert rig.web.post("/llm/mistral/v1/messages", json=body()).status_code == 404


def test_the_request_id_header_is_on_every_answer(rig: Rig) -> None:
    refused = rig.post(ANTHROPIC, body("mystery-model"))
    unauthorized = rig.post(ANTHROPIC, body(), token=None)
    ok = rig.post(ANTHROPIC, body())

    ids = {a.headers["x-keystone-request-id"] for a in (refused, unauthorized, ok)}
    assert len(ids) == 3 and all(len(i) == 26 for i in ids)


def test_the_provider_ids_are_the_ones_the_registry_reserves() -> None:
    assert set(UPSTREAM_IDS.values()) == LLM_UPSTREAM_IDS
    assert PATHS == {"anthropic": "/v1/messages", "openai": "/v1/chat/completions"}


# -- a whole answer that takes its time (KS-998)


class Slowly(httpx2.AsyncByteStream):
    """A body whose pieces arrive with a pause before each, as a long answer's do."""

    def __init__(self, chunks: list[bytes], pause_s: float) -> None:
        self.chunks = chunks
        self.pause_s = pause_s

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            await anyio.sleep(self.pause_s)
            yield chunk


def test_a_whole_answer_slower_than_a_drain_is_delivered_and_booked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DRAIN_S is the time given to the rest of an answer whose caller has left. A whole answer
    gets `llm_proxy.timeout_s`. Under the drain limit, a body that took longer was cut after the
    200 had gone out: the SDK got an empty body, and the ledger a cost of nothing for an answer
    the provider had finished and charged for."""
    import keystone.metering.llm_proxy as proxy_module

    monkeypatch.setattr(proxy_module, "DRAIN_S", 0.05)
    answer_body = json.dumps(
        {
            "id": "msg_slow",
            "type": "message",
            "role": "assistant",
            "model": "fake-model",
            "content": [{"type": "text", "text": "a slow answer"}],
            "usage": {"input_tokens": 4, "output_tokens": 12},
        }
    ).encode()

    def slow(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            headers={"content-type": "application/json"},
            stream=Slowly([answer_body[:20], answer_body[20:]], pause_s=0.1),
        )

    rig = build(transport=httpx2.MockTransport(slow), llm={"timeout_s": 5})

    with capture_logs() as logs:
        answer = rig.post(ANTHROPIC, body())

    assert answer.status_code == 200
    assert answer.json()["usage"] == {"input_tokens": 4, "output_tokens": 12}
    entry = only_entry(rig)
    assert (entry.input_tokens, entry.output_tokens, entry.cost_usd) == (4, 12, Decimal("0.000192"))
    assert not [e for e in logs if e["event"] == "llm_usage_incomplete"]
