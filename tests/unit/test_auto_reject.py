"""KS-705: the approver who rejects everything, against a stand-in for the admin API.

The smoke of Phase 7 uses it as the person in the demo. These tests hold what it promises: every
waiting request is rejected once, with a note, and what the card shows is printed for a script to
read.
"""

import json
from typing import Any

import anyio
import httpx2
import pytest

from examples.agents.auto_reject import API, AutoReject, card

pytestmark = pytest.mark.phase(7)

ATTACK = {
    "id": "01JATTACK",
    "tool": "mail__send_email",
    "risk": "high",
    "reasons": ["tainted-external-effect", "rule-of-two", "external-email-needs-approval"],
    "tainted": True,
    "flags": ["reads_untrusted", "reads_sensitive"],
    "arguments": {"to": "attacker@evil.test"},
    "requested_by_user": "olivia",
    "session_id": "s-1",
}


class FakeApi:
    """The two routes the approver uses. It keeps what it was sent."""

    def __init__(self, waiting: list[dict[str, Any]], refuse_first_token: bool = False) -> None:
        self.waiting = list(waiting)
        self.decisions: list[tuple[str, dict[str, Any]]] = []
        self.tokens: list[str] = []
        self.taken: set[str] = set()
        self._refuse = refuse_first_token

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        bearer = request.headers.get("authorization", "")
        self.tokens.append(bearer)
        if self._refuse and bearer == "Bearer first":
            return httpx2.Response(401, json={"error": "expired"})
        path = request.url.path
        if request.method == "GET" and path == f"{API}/approvals":
            assert request.url.params["status"] == "pending"
            return httpx2.Response(200, json=self.waiting)
        if request.method == "POST" and path.startswith(f"{API}/approvals/"):
            approval_id = path.split("/")[-2]
            body = json.loads(request.content)
            if approval_id in self.taken:
                return httpx2.Response(409, json={"error": "already decided"})
            self.decisions.append((approval_id, body))
            self.waiting = [w for w in self.waiting if w["id"] != approval_id]
            return httpx2.Response(200, json={"id": approval_id, "status": "rejected"})
        return httpx2.Response(404)


def approver(
    api: FakeApi, lines: list[dict[str, Any]], tokens: list[str] | None = None
) -> tuple[AutoReject, httpx2.AsyncClient]:
    issued = iter(tokens or ["token"])
    client = httpx2.AsyncClient(
        base_url="http://keystone.test", transport=httpx2.MockTransport(api.handle)
    )
    return AutoReject(client, lambda: next(issued), note="not this time", emit=lines.append), client


async def test_every_waiting_request_is_rejected_once_with_the_note() -> None:
    other = {**ATTACK, "id": "01JOTHER", "tool": "bank__transfer"}
    api, lines = FakeApi([ATTACK, other]), list[dict[str, Any]]()
    rejecting, client = approver(api, lines)

    async with client:
        first = await rejecting.sweep()
        second = await rejecting.sweep()

    assert [d for d, _ in api.decisions] == ["01JATTACK", "01JOTHER"]
    assert all(body == {"approve": False, "note": "not this time"} for _, body in api.decisions)
    assert len(first) == 2 and second == []  # nothing is waiting any more
    assert [line["id"] for line in lines] == ["01JATTACK", "01JOTHER"]


async def test_the_line_it_prints_is_what_the_card_shows() -> None:
    api, lines = FakeApi([ATTACK]), list[dict[str, Any]]()
    rejecting, client = approver(api, lines)

    async with client:
        await rejecting.sweep()

    [line] = lines
    assert line == card(ATTACK, "not this time", "rejected")
    assert line["tainted"] is True
    assert line["flags"] == ["reads_sensitive", "reads_untrusted"]
    assert line["reasons"] == [
        "external-email-needs-approval",
        "rule-of-two",
        "tainted-external-effect",
    ]
    assert json.loads(json.dumps(line)) == line  # a line of JSON for a script


async def test_a_request_that_someone_else_decided_first_is_not_an_error() -> None:
    api, lines = FakeApi([ATTACK]), list[dict[str, Any]]()
    api.taken.add("01JATTACK")
    rejecting, client = approver(api, lines)

    async with client:
        done = await rejecting.sweep()

    assert done == [] and lines == [] and rejecting.rejected == []


async def test_a_token_that_expired_is_replaced_once() -> None:
    api, lines = FakeApi([ATTACK], refuse_first_token=True), list[dict[str, Any]]()
    rejecting, client = approver(api, lines, tokens=["first", "second"])

    async with client:
        await rejecting.sweep()

    assert [d for d, _ in api.decisions] == ["01JATTACK"]
    assert api.tokens[0] == "Bearer first" and set(api.tokens[1:]) == {"Bearer second"}


async def test_a_run_goes_on_after_a_failed_pass_and_stops_at_its_time() -> None:
    calls = {"n": 0}

    def flaky(request: httpx2.Request) -> httpx2.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx2.Response(503)
        return httpx2.Response(200, json=[])

    client = httpx2.AsyncClient(
        base_url="http://keystone.test", transport=httpx2.MockTransport(flaky)
    )
    rejecting = AutoReject(client, lambda: "token", emit=lambda line: None)

    async with client:
        with anyio.fail_after(5):
            await rejecting.run(interval_s=0.01, duration_s=0.2)

    assert calls["n"] > 1
