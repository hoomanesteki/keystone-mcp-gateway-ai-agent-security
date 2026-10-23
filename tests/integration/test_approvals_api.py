"""KS-604: the approvals API an approver or the console uses, and the webhook that tells others.

Requests are made the way an agent makes them (a transfer through the MCP endpoint, held for
approval) or, for the other tenant, by a service of the test's own. Decisions are made through the
admin API with tokens of the realm's people: lena (approver), root (admin), alice and olivia (no
approval role) and a made-up approver of globex.
"""

import hashlib
import hmac
import json
import time
from collections.abc import Callable
from typing import Any

import anyio
import httpx2
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from keystone.approvals.service import ApprovalService
from keystone.settings import ApprovalSettings
from tests.fixtures.calls import make_ctx, make_tool
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp, McpConnect
from tests.fixtures.servers import ServerThread
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(6), pytest.mark.services]

API = "/admin/api/v1"
Factory = Callable[..., KeystoneApp]
BIG = {"from_account": "CHK-001", "to": "SAV-002", "amount": 900}
SECRET = "webhook-secret-for-the-test"


def call(
    app: KeystoneApp, method: str, path: str, token: str | None, **options: Any
) -> httpx2.Response:
    sent = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx2.request(method, f"{app.base}{API}{path}", headers=sent, timeout=15, **options)


def person(idp: FakeIdp, user: str, *roles: str, tenant: str = "acme") -> str:
    return idp.make_token(
        user, tenant, groups=(f"/tenants/{tenant}",), azp="keystone-cli", roles=roles
    )


async def hold_transfers(app: KeystoneApp, mcp_client: McpConnect, *amounts: int) -> list[str]:
    """Olivia asks for transfers that need approval and is told they are pending. The ids."""
    ids = []
    async with mcp_client(app, user="olivia") as olivia:
        for amount in amounts:
            result = await olivia.call_tool("bank__transfer", {**BIG, "amount": amount})
            assert result.meta is not None and result.meta["keystone/code"] == "KS_APPROVAL_PENDING"
            ids.append(str(result.meta["keystone/approval_id"]))
    return ids


async def test_list_pending_for_tenant(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    approval_service: ApprovalService,
    fake_idp: FakeIdp,
) -> None:
    app = keystone_app_factory(globex=True)
    first, second = await hold_transfers(app, mcp_client, 900, 700)
    # A request of the other tenant, made by a service of the test's own.
    elsewhere = make_ctx(BIG, make_tool("crm", "export_contacts"), principal=BOB)
    theirs = await approval_service.request(elsewhere, ["globex-rule"])
    lena = person(fake_idp, "lena", "approver")
    gina = person(fake_idp, "gina", "approver", tenant="globex")

    mine = call(app, "GET", "/approvals", lena)
    other = call(app, "GET", "/approvals?status=pending", gina)

    assert mine.status_code == 200
    items = mine.json()
    # The queue shows the request that has waited longest first, and only this tenant's.
    assert [i["id"] for i in items] == [first, second]
    assert [i["id"] for i in other.json()] == [theirs]
    top = items[0]
    assert (top["status"], top["tool"], top["risk"]) == ("pending", "bank__transfer", "high")
    assert top["tags"] == ["external_effect"]
    assert top["arguments"] == {**BIG, "amount": 900}
    assert top["reasons"] == ["approve-transfer-over-500"]
    assert (top["requested_by_user"], top["requested_by_agent"]) == ("olivia", "ops-agent")
    assert top["own_request"] is False
    assert 0 < top["expires_in_s"] <= 900 and top["expires_at"].endswith("Z")
    assert top["flags"] == [] and top["tainted"] is False
    assert top["decided_by"] is None and top["decision_note"] is None
    # The other tenant's request is for a tool Keystone has no row for: no risk is invented.
    assert other.json()[0]["risk"] is None

    # By status, and the page size is checked.
    assert call(app, "GET", "/approvals?status=approved", lena).json() == []
    assert call(app, "GET", "/approvals?limit=1", lena).json()[0]["id"] == first
    for bad in ("status=maybe", "limit=0", "limit=201"):
        assert call(app, "GET", f"/approvals?{bad}", lena).status_code == 422, bad
    # Admins see the queue too; people with neither role and strangers do not.
    assert call(app, "GET", "/approvals", fake_idp.token_for("root")).status_code == 200
    assert call(app, "GET", "/approvals", fake_idp.token_for("alice")).status_code == 403
    assert call(app, "GET", "/approvals", None).status_code == 401


BOB = make_ctx().principal.model_copy(
    update={"tenant_id": "globex", "user_id": "bob", "groups": (), "agent_id": "support-agent"}
)


async def test_decision_requires_approver(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    fake_idp: FakeIdp,
) -> None:
    app = keystone_app_factory(globex=True)
    ids = await hold_transfers(app, mcp_client, 900, 800, 700)
    approve = {"approve": True, "note": "fine"}

    def decide(approval_id: str, token: str | None, body: Any = approve) -> httpx2.Response:
        return call(app, "POST", f"/approvals/{approval_id}/decision", token, json=body)

    # Without the role, or the token: 403 and 401.
    assert decide(ids[0], fake_idp.token_for("alice")).status_code == 403
    assert decide(ids[0], fake_idp.token_for("olivia")).status_code == 403
    assert decide(ids[0], None).status_code == 401
    # Olivia made the request: even with the approver role she cannot decide it.
    own = decide(ids[0], person(fake_idp, "olivia", "approver"))
    assert own.status_code == 403 and own.json()["error"] == "forbidden"
    # An approver of another tenant does not find it.
    foreign = decide(ids[0], person(fake_idp, "gina", "approver", tenant="globex"))
    assert foreign.status_code == 404 and foreign.json()["error"] == "not_found"
    assert decide("01JNOSUCHREQUEST000000000", fake_idp.token_for("lena")).status_code == 404
    assert demo_upstreams.state("bank")["transfers"] == []

    # Lena approves, root rejects with a note; each answer is the request as it now stands.
    approved = decide(ids[0], fake_idp.token_for("lena"))
    assert approved.status_code == 200
    body = approved.json()
    assert (body["id"], body["status"]) == (ids[0], "approved")
    assert (body["decided_by"], body["decision_note"]) == ("lena", "fine")
    rejected = decide(ids[1], fake_idp.token_for("root"), {"approve": False, "note": "no"})
    assert rejected.status_code == 200 and rejected.json()["status"] == "rejected"
    assert rejected.json()["decided_by"] == "root"

    # A request that is no longer pending is a 409 that says what it is now.
    for token in (fake_idp.token_for("lena"), fake_idp.token_for("root")):
        again = decide(ids[0], token, {"approve": False})
        assert again.status_code == 409
        assert again.json() == {
            "error": "conflict",
            "reason": "the request is approved",
            "status": "approved",
        }
    assert decide(ids[1], fake_idp.token_for("lena")).json()["status"] == "rejected"

    # The body is checked: the decision must be a boolean, and a note has a limit.
    for bad in (
        {},
        {"approve": "yes"},
        {"approve": True, "note": "x" * 501},
        {"approve": True, "x": 1},
    ):
        refused = decide(ids[2], fake_idp.token_for("lena"), bad)
        assert refused.status_code == 422, bad
    assert (
        call(app, "GET", f"/approvals/{ids[2]}", fake_idp.token_for("lena")).json()["status"]
        == "pending"
    )


async def test_a_request_that_expired_is_a_409_and_a_decided_one_stays_decided(
    keystone_app_factory: Factory, mcp_client: McpConnect, fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory(
        settings={"approvals": ApprovalSettings(wait_seconds=0, ttl_seconds=1, sweep_interval_s=60)}
    )
    [approval_id] = await hold_transfers(app, mcp_client, 900)
    lena = fake_idp.token_for("lena")
    await anyio.sleep(1.5)  # the sweeper has not run: the clock decides

    late = call(app, "POST", f"/approvals/{approval_id}/decision", lena, json={"approve": True})

    assert late.status_code == 409 and late.json()["status"] == "expired"
    assert call(app, "GET", f"/approvals/{approval_id}", lena).json()["status"] == "expired"
    assert call(app, "GET", "/approvals", lena).json() == []


async def test_the_detail_has_the_context_an_approver_needs(
    keystone_app_factory: Factory, mcp_client: McpConnect, fake_idp: FakeIdp, redis: Any
) -> None:
    app = keystone_app_factory(globex=True)
    async with mcp_client(app, user="olivia") as olivia:
        await olivia.call_tool("bank__get_balance", {"account": "CHK-001"})
        await olivia.call_tool("echo__echo", {"payload": "hello"})
        await olivia.call_tool("echo__echo", {"payload": 7})  # refused: the arguments do not fit
        # What the scanner will set in Phase 7: the session is tainted and has read sensitive data.
        [key] = await redis.keys("ks:sess:*")
        state = json.loads(await redis.get(key))
        state |= {"flags": ["reads_sensitive", "reads_untrusted"], "tainted": True}
        await redis.set(key, json.dumps(state), ex=3600)
        result = await olivia.call_tool("bank__transfer", BIG)
    approval_id = str(result.meta["keystone/approval_id"])  # type: ignore[index]
    app.audit.wait()

    detail = call(app, "GET", f"/approvals/{approval_id}", fake_idp.token_for("lena"))

    assert detail.status_code == 200
    body = detail.json()
    assert body["flags"] == ["reads_sensitive", "reads_untrusted"] and body["tainted"] is True
    # The session's last calls, newest first, as the audit explorer shows them.
    recent = body["recent_calls"]
    assert [(r["tool_name"], r["outcome"]) for r in recent] == [
        ("bank__transfer", "rejected"),  # the call that was told to wait
        ("echo__echo", "rejected"),
        ("echo__echo", "ok"),
        ("bank__get_balance", "ok"),
    ]
    assert recent[0]["reject_code"] == "KS_APPROVAL_PENDING" and recent[0]["hash"]
    assert recent[1]["reject_code"] == "KS_INVALID_ARGUMENTS"
    assert all(r["session_id"] == body["session_id"] for r in recent)
    # Not found, for an id that does not exist and for one of another tenant.
    lena = fake_idp.token_for("lena")
    assert call(app, "GET", "/approvals/01JNOSUCHREQUEST000000000", lena).status_code == 404
    gina = person(fake_idp, "gina", "approver", tenant="globex")
    assert call(app, "GET", f"/approvals/{approval_id}", gina).status_code == 404


async def test_only_ten_calls_of_the_session_are_shown(
    keystone_app_factory: Factory, mcp_client: McpConnect, fake_idp: FakeIdp
) -> None:
    app = keystone_app_factory()
    async with mcp_client(app, user="olivia") as olivia:
        for n in range(14):
            await olivia.call_tool("echo__echo", {"payload": str(n)})
        result = await olivia.call_tool("bank__transfer", BIG)
    app.audit.wait()

    detail = call(
        app,
        "GET",
        f"/approvals/{result.meta['keystone/approval_id']}",  # type: ignore[index]
        fake_idp.token_for("lena"),
    ).json()

    assert len(detail["recent_calls"]) == 10
    seqs = [r["seq"] for r in detail["recent_calls"]]
    assert seqs == sorted(seqs, reverse=True)


async def test_the_other_admin_routes_still_need_the_admin_role(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    """Widening the approvals routes to approvers must not widen anything else."""
    lena = fake_idp.token_for("lena")
    for path in ("/audit", "/tools", "/upstreams", "/sessions", "/policies"):
        assert call(keystone_app, "GET", path, lena).status_code == 403, path
    assert call(keystone_app, "POST", "/policies/reload", lena).status_code == 403
    assert call(keystone_app, "GET", "/audit", fake_idp.token_for("root")).status_code == 200


async def test_the_schema_describes_the_approvals_routes(keystone_app: KeystoneApp) -> None:
    schema = httpx2.get(f"{keystone_app.base}{API}/openapi.json", timeout=10).json()

    assert {"/approvals", "/approvals/{approval_id}", "/approvals/{approval_id}/decision"} <= set(
        schema["paths"]
    )
    decision = schema["paths"]["/approvals/{approval_id}/decision"]["post"]
    assert {"200", "403", "404", "409", "503"} <= set(decision["responses"])
    one = schema["paths"]["/approvals/{approval_id}"]["get"]
    assert {"200", "404", "503"} <= set(one["responses"])
    assert "503" in schema["paths"]["/approvals"]["get"]["responses"]
    assert "ApprovalItem" in schema["components"]["schemas"]


# -- the webhook


class Receiver:
    """A web server that notes what it is sent and answers as it is told to."""

    def __init__(self, statuses: list[int], *, delay_s: float = 0.0) -> None:
        self.statuses = list(statuses)
        self.delay_s = delay_s
        self.received: list[tuple[dict[str, str], bytes]] = []
        self.thread = ServerThread(Starlette(routes=[Route("/hook", self._hook, methods=["POST"])]))

    async def _hook(self, request: Request) -> Response:
        self.received.append(
            ({k.lower(): v for k, v in request.headers.items()}, await request.body())
        )
        if self.delay_s:
            await anyio.sleep(self.delay_s)
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return JSONResponse({"ok": status < 400}, status_code=status)

    @property
    def url(self) -> str:
        return f"{self.thread.url}/hook"

    def __enter__(self) -> "Receiver":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.thread.stop()


def signed_correctly(headers: dict[str, str], body: bytes) -> bool:
    expected = hmac.new(
        SECRET.encode(), headers["x-keystone-timestamp"].encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(headers["x-keystone-signature"], f"sha256={expected}")


async def wait_for(check: Callable[[], bool], seconds: float = 20) -> None:
    with anyio.fail_after(seconds):
        while True:
            if check():
                return
            await anyio.sleep(0.1)


def hooked(url: str, **more: Any) -> dict[str, Any]:
    """Settings for an app that tells a webhook, quickly: three retries 0.1 s apart."""
    return {
        "approvals": ApprovalSettings(
            wait_seconds=0,
            poll_interval_s=0.2,
            webhook_url=url,
            webhook_backoff_s=[0.1, 0.1, 0.1],
            **more,
        )
    }


async def test_webhook_signed_and_retried(
    keystone_app_factory: Factory, mcp_client: McpConnect, demo_upstreams: DemoUpstreams
) -> None:
    with Receiver([500, 200]) as receiver:
        app = keystone_app_factory(
            settings=hooked(receiver.url),
            environ={"KEYSTONE_APPROVALS_WEBHOOK_SECRET": SECRET},
        )
        [approval_id] = await hold_transfers(app, mcp_client, 900)

        await wait_for(lambda: len(receiver.received) >= 2)

    first, second = receiver.received
    # Both attempts carry a signature that checks, made over the bytes that were sent.
    for headers, body in (first, second):
        assert headers["content-type"] == "application/json"
        assert headers["x-keystone-signature"].startswith("sha256=")
        assert signed_correctly(headers, body)
        assert abs(int(headers["x-keystone-timestamp"]) - time.time()) < 60
    payload = json.loads(second[1])
    assert payload == {
        "id": approval_id,
        "tenant": "acme",
        "tool": "bank__transfer",
        "requester": "olivia",
        "agent": "ops-agent",
        "reasons": ["approve-transfer-over-500"],
        "expires_at": payload["expires_at"],
        "console_url": f"http://localhost:5173/approvals?id={approval_id}",
    }
    # The arguments are not sent. The body is the same text on a retry.
    assert b"CHK-001" not in second[1] and first[1] == second[1]


async def test_a_signature_made_with_another_secret_does_not_check() -> None:
    headers = {"x-keystone-timestamp": "1700000000", "x-keystone-signature": "sha256=" + "0" * 64}

    assert signed_correctly(headers, b"{}") is False


async def test_the_webhook_never_delays_the_call_and_gives_up_after_three_retries(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    with Receiver([503], delay_s=0.5) as receiver:
        app = keystone_app_factory(
            settings=hooked(receiver.url),
            environ={"KEYSTONE_APPROVALS_WEBHOOK_SECRET": SECRET},
        )
        started = time.monotonic()
        await hold_transfers(app, mcp_client, 900)
        call_took = time.monotonic() - started

        await wait_for(lambda: len(receiver.received) >= 4)
        await anyio.sleep(1.0)  # a fifth would have arrived by now

    assert call_took < 2.0  # four slow attempts would have taken 2 s on their own
    assert len(receiver.received) == 4  # the first and three retries


async def test_a_refusal_from_the_receiver_is_not_retried(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    with Receiver([401]) as receiver:
        app = keystone_app_factory(
            settings=hooked(receiver.url),
            environ={"KEYSTONE_APPROVALS_WEBHOOK_SECRET": SECRET},
        )
        await hold_transfers(app, mcp_client, 900)

        await wait_for(lambda: len(receiver.received) >= 1)
        await anyio.sleep(1.0)

    assert len(receiver.received) == 1


async def test_a_webhook_that_cannot_be_reached_does_not_fail_the_call(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory(
        settings=hooked("http://127.0.0.1:1/hook"),
        environ={"KEYSTONE_APPROVALS_WEBHOOK_SECRET": SECRET},
    )

    [approval_id] = await hold_transfers(app, mcp_client, 900)

    assert approval_id
