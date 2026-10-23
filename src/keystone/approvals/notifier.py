"""Tell people and tools that an approval is waiting (KS-604).

When a request is made, Keystone can `POST` a JSON description of it to a webhook, and a plain
message with a link to the console to a Slack incoming webhook. Neither ever delays or fails the
call that asked: `notify` puts the request on a queue and returns, and a task delivers it.

The webhook is signed so that the receiver can check it came from Keystone and is fresh:

    X-Keystone-Timestamp: <unix seconds>
    X-Keystone-Signature: sha256=<hex HMAC-SHA256 of timestamp + "." + body, keyed by the secret>

The signature covers the exact bytes sent. Each attempt is signed again with the time of that
attempt, so a receiver that refuses old timestamps does not refuse a retry. The secret comes from
the environment (`KEYSTONE_APPROVALS_WEBHOOK_SECRET`), never from the config file, and a webhook
without one is refused at startup: an unsigned webhook cannot be told from a forged one.

A delivery is tried up to four times, the first and three retries, with 1, 2 and 4 seconds between
them; each attempt gives up after 5 seconds. A network error, a timeout, a 408, a 429 and a 5xx are
retried. Any other answer ends the delivery, since sending it again cannot change a receiver's
mind. Failures are logged with the receiver's host and never with its address, which can carry a
secret (a Slack address always does). Nothing about the call's arguments is sent: the payload names
the tool, the requester, the reasons and the expiry, and the console shows the rest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

import anyio
import httpx2
import structlog
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from pydantic import SecretStr

from keystone.approvals.service import ApprovalRecord

log = structlog.get_logger()

WEBHOOK_SECRET_ENV = "KEYSTONE_APPROVALS_WEBHOOK_SECRET"  # noqa: S105 - the name, not a secret
ATTEMPT_TIMEOUT_S = 5.0
BACKOFF_S: tuple[float, ...] = (1.0, 2.0, 4.0)
QUEUE_SIZE = 100
CONCURRENT_DELIVERIES = 8
RETRY_STATUSES = frozenset({408, 429})


class ApprovalConfigError(ValueError):
    """The approval notifications are set up in a way that cannot work. The message names the
    problem and never repeats a secret."""


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """`sha256=` and the hex HMAC-SHA256 of `timestamp + "." + body`."""
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def console_link(console_origin: str, approval_id: str) -> str:
    return f"{console_origin.rstrip('/')}/approvals?id={approval_id}"


def webhook_payload(record: ApprovalRecord, console_origin: str) -> dict[str, object]:
    return {
        "id": record.id,
        "tenant": record.tenant_id,
        "tool": record.tool_name,
        "requester": record.requested_by_user,
        "agent": record.requested_by_agent,
        "reasons": list(record.reasons),
        "expires_at": record.expires_at.isoformat(),
        "console_url": console_link(console_origin, record.id),
    }


def slack_payload(record: ApprovalRecord, console_origin: str) -> dict[str, str]:
    reasons = ", ".join(record.reasons) or "no reason given"
    return {
        "text": (
            f"Approval needed in {record.tenant_id}: {record.requested_by_user} "
            f"({record.requested_by_agent}) wants to call {record.tool_name} ({reasons}). "
            f"{console_link(console_origin, record.id)}"
        )
    }


@dataclass(frozen=True)
class Attempt:
    sent: bool
    retry: bool
    outcome: str  # what to log: an HTTP status, or the type of the error


class ApprovalNotifier:
    def __init__(
        self,
        *,
        console_origin: str,
        webhook_url: str | None = None,
        webhook_secret: SecretStr | None = None,
        slack_url: SecretStr | None = None,
        backoff_s: Sequence[float] = BACKOFF_S,
        attempt_timeout_s: float = ATTEMPT_TIMEOUT_S,
        client: httpx2.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if webhook_url and not (webhook_secret and webhook_secret.get_secret_value()):
            raise ApprovalConfigError(
                f"approvals.webhook_url is set, so {WEBHOOK_SECRET_ENV} must be set: "
                "an unsigned webhook cannot be told from a forged one"
            )
        self._console_origin = console_origin
        self._webhook_url = webhook_url
        self._secret = webhook_secret
        self._slack = slack_url
        self._backoff_s = tuple(backoff_s)
        self._attempt_timeout_s = attempt_timeout_s
        self._client = client
        self._clock = clock
        self._send: MemoryObjectSendStream[ApprovalRecord]
        self._receive: MemoryObjectReceiveStream[ApprovalRecord]
        self._send, self._receive = anyio.create_memory_object_stream[ApprovalRecord](QUEUE_SIZE)

    @property
    def enabled(self) -> bool:
        return bool(self._webhook_url or self._slack)

    def notify(self, record: ApprovalRecord) -> None:
        """Queue the request for delivery and return. Never blocks and never raises: a full queue
        drops the notification and logs it, because the call that asked must not wait for this."""
        if not self.enabled:
            return
        try:
            self._send.send_nowait(record)
        except anyio.WouldBlock:
            log.error("approval_notification_dropped", approval=record.id, reason="queue_full")
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            log.warning("approval_notification_dropped", approval=record.id, reason="stopped")

    async def run(self) -> None:
        """Deliver what is queued, until cancelled. A few deliveries run at once, so one slow
        receiver does not hold up the next request's notification."""
        limiter = anyio.CapacityLimiter(CONCURRENT_DELIVERIES)
        async with anyio.create_task_group() as tasks:
            async for record in self._receive:
                await limiter.acquire_on_behalf_of(record.id)
                tasks.start_soon(self._deliver_and_release, record, limiter)

    async def _deliver_and_release(
        self, record: ApprovalRecord, limiter: anyio.CapacityLimiter
    ) -> None:
        try:
            await self.deliver(record)
        except Exception as exc:
            log.error("approval_notification_failed", approval=record.id, error=type(exc).__name__)
        finally:
            limiter.release_on_behalf_of(record.id)

    async def deliver(self, record: ApprovalRecord) -> None:
        """Send the request to each receiver that is set up. A receiver that cannot be reached
        is logged and does not stop the other."""
        owned = self._client is None
        http = self._client or httpx2.AsyncClient(
            timeout=httpx2.Timeout(self._attempt_timeout_s), follow_redirects=False
        )
        try:
            async with anyio.create_task_group() as tasks:
                if self._webhook_url and self._secret:
                    secret = self._secret.get_secret_value()
                    tasks.start_soon(self._webhook, http, record, self._webhook_url, secret)
                if self._slack:
                    tasks.start_soon(
                        self._slack_message, http, record, self._slack.get_secret_value()
                    )
        finally:
            if owned:
                await http.aclose()

    async def _webhook(
        self, http: httpx2.AsyncClient, record: ApprovalRecord, url: str, secret: str
    ) -> None:
        body = json.dumps(
            webhook_payload(record, self._console_origin), separators=(",", ":"), sort_keys=True
        ).encode()

        def headers() -> dict[str, str]:
            timestamp = str(int(self._clock()))
            return {
                "Content-Type": "application/json",
                "X-Keystone-Timestamp": timestamp,
                "X-Keystone-Signature": sign(secret, timestamp, body),
            }

        await self._post_with_retries(http, url, body, headers, record.id, "webhook")

    async def _slack_message(
        self, http: httpx2.AsyncClient, record: ApprovalRecord, url: str
    ) -> None:
        body = json.dumps(slack_payload(record, self._console_origin)).encode()
        plain = {"Content-Type": "application/json"}
        await self._post_with_retries(http, url, body, lambda: plain, record.id, "slack")

    async def _post_with_retries(
        self,
        http: httpx2.AsyncClient,
        url: str,
        body: bytes,
        headers: Callable[[], Mapping[str, str]],
        approval_id: str,
        kind: str,
    ) -> None:
        attempts = len(self._backoff_s) + 1
        for number in range(1, attempts + 1):
            attempt = await self._attempt(http, url, body, headers())
            if attempt.sent:
                log.info("approval_notified", approval=approval_id, kind=kind, attempt=number)
                return
            log.warning(
                "approval_notification_attempt_failed",
                approval=approval_id,
                kind=kind,
                attempt=number,
                host=urlsplit(url).hostname or "unknown",
                outcome=attempt.outcome,
            )
            if not attempt.retry or number == attempts:
                break
            await anyio.sleep(self._backoff_s[number - 1])
        log.error("approval_notification_given_up", approval=approval_id, kind=kind)

    async def _attempt(
        self, http: httpx2.AsyncClient, url: str, body: bytes, headers: Mapping[str, str]
    ) -> Attempt:
        try:
            with anyio.fail_after(self._attempt_timeout_s):
                response = await http.post(url, content=body, headers=dict(headers))
        except Exception as exc:
            # The type only: the text of a network error can hold the address.
            return Attempt(sent=False, retry=True, outcome=type(exc).__name__)
        status = response.status_code
        if 200 <= status < 300:
            return Attempt(sent=True, retry=False, outcome=str(status))
        retry = status >= 500 or status in RETRY_STATUSES
        return Attempt(sent=False, retry=retry, outcome=str(status))
