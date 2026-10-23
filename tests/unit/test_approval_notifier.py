"""KS-604: the webhook and the Slack message that tell others an approval is waiting.

The receiver is `httpx2.MockTransport`, so the signature, the retries, the timeouts and what is
logged can be read without a network.
"""

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import anyio
import httpx2
import pytest
from pydantic import SecretStr
from structlog.testing import capture_logs

from keystone.approvals.notifier import (
    ApprovalConfigError,
    ApprovalNotifier,
    sign,
    slack_payload,
    webhook_payload,
)
from keystone.approvals.service import ApprovalRecord

pytestmark = pytest.mark.phase(6)

SECRET = "webhook-secret-for-the-test"
SLACK = "https://hooks.slack.test/services/T000/B000/not-for-the-logs"
ORIGIN = "http://localhost:5173"
QUICK = (0.0, 0.0, 0.0)


def record(approval_id: str = "01JAPPROVAL") -> ApprovalRecord:
    now = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
    return ApprovalRecord(
        id=approval_id,
        tenant_id="acme",
        session_id="session-1",
        call_id="01JCALL",
        tool_name="bank__transfer",
        args_redacted={"from_account": "CHK-001", "amount": 900},
        args_digest="d",
        reasons=("approve-transfer-over-500",),
        status="pending",
        requested_by_user="olivia",
        requested_by_agent="ops-agent",
        decided_by=None,
        decision_note=None,
        requested_at=now,
        decided_at=None,
        expires_at=now + timedelta(minutes=15),
        expires_in_s=900.0,
    )


class Receiver:
    """Answers with the statuses it is given, in order, and notes every request."""

    def __init__(self, *statuses: int | Exception) -> None:
        self.statuses = list(statuses)
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        answer = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        if isinstance(answer, Exception):
            raise answer
        return httpx2.Response(answer)

    def client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(self))


def notifier(receiver: Receiver, **options: object) -> ApprovalNotifier:
    return ApprovalNotifier(
        console_origin=ORIGIN,
        webhook_url="https://hooks.example.test/keystone",
        webhook_secret=SecretStr(SECRET),
        backoff_s=QUICK,
        client=receiver.client(),
        **options,  # type: ignore[arg-type]
    )


def test_the_signature_is_the_hmac_of_the_timestamp_a_dot_and_the_body() -> None:
    body = b'{"id":"01J"}'
    expected = hmac.new(SECRET.encode(), b"1700000000." + body, hashlib.sha256).hexdigest()

    assert sign(SECRET, "1700000000", body) == f"sha256={expected}"
    # Another secret, another timestamp or another body gives another signature.
    assert sign("another", "1700000000", body) != sign(SECRET, "1700000000", body)
    assert sign(SECRET, "1700000001", body) != sign(SECRET, "1700000000", body)
    assert sign(SECRET, "1700000000", b"{}") != sign(SECRET, "1700000000", body)


def test_the_payload_names_the_request_and_never_the_arguments() -> None:
    payload = webhook_payload(record(), ORIGIN)

    assert payload == {
        "id": "01JAPPROVAL",
        "tenant": "acme",
        "tool": "bank__transfer",
        "requester": "olivia",
        "agent": "ops-agent",
        "reasons": ["approve-transfer-over-500"],
        "expires_at": "2026-10-23T12:15:00+00:00",
        "console_url": "http://localhost:5173/approvals?id=01JAPPROVAL",
    }
    assert "CHK-001" not in json.dumps(payload) and "900" not in json.dumps(payload)


def test_the_slack_message_is_plain_text_with_a_link_to_the_console() -> None:
    assert slack_payload(record(), "http://localhost:5173/") == {
        "text": (
            "Approval needed in acme: olivia (ops-agent) wants to call bank__transfer "
            "(approve-transfer-over-500). http://localhost:5173/approvals?id=01JAPPROVAL"
        )
    }


async def test_a_delivery_is_signed_over_the_bytes_that_were_sent() -> None:
    receiver = Receiver(200)

    await notifier(receiver, clock=lambda: 1_700_000_000.4).deliver(record())

    [request] = receiver.requests
    body = request.content
    assert request.method == "POST" and str(request.url) == "https://hooks.example.test/keystone"
    assert request.headers["content-type"] == "application/json"
    assert request.headers["x-keystone-timestamp"] == "1700000000"
    assert request.headers["x-keystone-signature"] == sign(SECRET, "1700000000", body)
    assert json.loads(body)["id"] == "01JAPPROVAL"


async def test_a_500_is_retried_and_each_attempt_is_signed_with_its_own_time() -> None:
    receiver = Receiver(500, 200)
    clock = iter([1_700_000_000.0, 1_700_000_001.0])

    await notifier(receiver, clock=lambda: next(clock)).deliver(record())

    first, second = receiver.requests
    assert first.content == second.content  # the same text
    assert [r.headers["x-keystone-timestamp"] for r in (first, second)] == [
        "1700000000",
        "1700000001",
    ]
    for request in (first, second):
        stamp = request.headers["x-keystone-timestamp"]
        assert request.headers["x-keystone-signature"] == sign(SECRET, stamp, request.content)


async def test_a_delivery_that_keeps_failing_is_tried_four_times_and_then_given_up() -> None:
    receiver = Receiver(503)

    with capture_logs() as logs:
        await notifier(receiver).deliver(record())  # does not raise

    assert len(receiver.requests) == 4  # the first and three retries
    events = [entry["event"] for entry in logs]
    assert events.count("approval_notification_attempt_failed") == 4
    assert events[-1] == "approval_notification_given_up"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410])
async def test_an_answer_that_a_retry_cannot_change_is_not_retried(status: int) -> None:
    receiver = Receiver(status)

    await notifier(receiver).deliver(record())

    assert len(receiver.requests) == 1


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
async def test_these_answers_are_retried(status: int) -> None:
    receiver = Receiver(status, 204)

    await notifier(receiver).deliver(record())

    assert len(receiver.requests) == 2


async def test_a_network_error_is_retried() -> None:
    receiver = Receiver(httpx2.ConnectError("no route"), httpx2.ReadTimeout("slow"), 200)

    await notifier(receiver).deliver(record())

    assert len(receiver.requests) == 3


async def test_an_attempt_that_takes_too_long_is_given_up_after_its_own_timeout() -> None:
    async def hang(request: httpx2.Request) -> httpx2.Response:
        await anyio.sleep(30)
        return httpx2.Response(200)

    slow = ApprovalNotifier(
        console_origin=ORIGIN,
        webhook_url="https://hooks.example.test/keystone",
        webhook_secret=SecretStr(SECRET),
        backoff_s=(0.0,),
        attempt_timeout_s=0.2,
        client=httpx2.AsyncClient(transport=httpx2.MockTransport(hang)),
    )

    with anyio.fail_after(5):
        await slow.deliver(record())  # two attempts of 0.2 s, and it returns


async def test_the_slack_message_is_sent_without_a_signature_and_its_address_is_not_logged() -> (
    None
):
    receiver = Receiver(500, 200)
    slack = ApprovalNotifier(
        console_origin=ORIGIN,
        slack_url=SecretStr(SLACK),
        backoff_s=QUICK,
        client=receiver.client(),
    )

    with capture_logs() as logs:
        await slack.deliver(record())

    _failed, second = receiver.requests
    assert str(second.url) == SLACK
    assert "x-keystone-signature" not in second.headers
    assert json.loads(second.content) == slack_payload(record(), ORIGIN)
    # The address holds a token. Logs name the host and nothing after it.
    shown = json.dumps(logs, default=str)
    assert "not-for-the-logs" not in shown and "T000" not in shown
    assert "hooks.slack.test" in shown


async def test_one_receiver_failing_does_not_stop_the_other() -> None:
    receiver = Receiver(500)  # every request fails, the webhook's and Slack's

    both = ApprovalNotifier(
        console_origin=ORIGIN,
        webhook_url="https://hooks.example.test/keystone",
        webhook_secret=SecretStr(SECRET),
        slack_url=SecretStr(SLACK),
        backoff_s=(0.0,),
        client=receiver.client(),
    )
    await both.deliver(record())

    hosts = sorted({request.url.host for request in receiver.requests})
    assert hosts == ["hooks.example.test", "hooks.slack.test"]
    assert len(receiver.requests) == 4  # two attempts each


async def test_the_secret_is_never_logged() -> None:
    receiver = Receiver(500)

    with capture_logs() as logs:
        await notifier(receiver).deliver(record())

    assert SECRET not in json.dumps(logs, default=str)


def test_a_webhook_without_a_secret_is_refused_and_says_where_the_secret_goes() -> None:
    for missing in (None, SecretStr("")):
        with pytest.raises(ApprovalConfigError, match="KEYSTONE_APPROVALS_WEBHOOK_SECRET"):
            ApprovalNotifier(
                console_origin=ORIGIN,
                webhook_url="https://hooks.example.test/keystone",
                webhook_secret=missing,
            )
    # Slack needs none: its address is the secret.
    assert ApprovalNotifier(console_origin=ORIGIN, slack_url=SecretStr(SLACK)).enabled


async def test_notify_queues_and_returns_and_a_task_delivers() -> None:
    receiver = Receiver(200)
    sender = notifier(receiver)
    started = anyio.current_time()

    sender.notify(record("01JFIRST"))
    sender.notify(record("01JSECOND"))
    assert anyio.current_time() - started < 0.1  # nothing was sent from the caller's task
    assert receiver.requests == []

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(sender.run)
        with anyio.fail_after(5):
            while True:
                if len(receiver.requests) >= 2:
                    break
                await anyio.sleep(0.02)
        tasks.cancel_scope.cancel()

    assert sorted(json.loads(r.content)["id"] for r in receiver.requests) == [
        "01JFIRST",
        "01JSECOND",
    ]


async def test_a_full_queue_drops_the_notification_and_never_blocks_or_raises() -> None:
    sender = notifier(Receiver(200))

    with capture_logs() as logs:
        for number in range(150):  # the queue holds 100 and nothing is taking from it
            sender.notify(record(f"01J{number:03d}"))

    dropped = [entry for entry in logs if entry["event"] == "approval_notification_dropped"]
    assert len(dropped) == 50 and dropped[0]["reason"] == "queue_full"


def test_a_notifier_with_nothing_to_tell_does_nothing() -> None:
    quiet = ApprovalNotifier(console_origin=ORIGIN)

    assert quiet.enabled is False
    quiet.notify(record())  # no queue entry, no error
