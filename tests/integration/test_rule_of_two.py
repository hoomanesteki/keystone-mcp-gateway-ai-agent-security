"""KS-705: the Rule of Two, through the real gateway.

A session that has read untrusted and sensitive data may not take an external action without a
person, and a session that read an injection may not either, and may not run a critical tool at
all (policies/default/**/rule_of_two.cedar, plan sections 3.5 and 3.8). The flags and the taint are
recorded by KS-704; these tests read an email, send one, and look at what the policy did.

The classifier is off in the test apps, so the poisoned email scores 0.88 from the rules alone.
`echo__echo` has no tag, so an injection sent through it taints a session and sets no flag: that is
how a test sees the taint rule apart from the rule of two flags.
"""

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import anyio
import pytest

from examples.upstreams import mail_server
from keystone.core.types import Risk
from keystone.registry.config import ToolOverride, UpstreamConfig
from keystone.settings import ApprovalSettings, PolicySettings
from tests.fixtures.approvals import Approver
from tests.fixtures.keystone import KeystoneApp, McpConnect, demo_tools
from tests.fixtures.mcp_results import one, texts
from tests.fixtures.policies import copy_pack, write_policies
from tests.fixtures.scan import INJECTION
from tests.fixtures.servers import ServerThread
from tests.fixtures.upstreams import DemoUpstreams

pytestmark = [pytest.mark.phase(7), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
AWAIT = "keystone__await_approval"
WHOAMI = "keystone__whoami"
INTERNAL = {"to": "colleague@acme.test", "subject": "Q3", "body": "The numbers are in."}
BENIGN_EMAIL = {"email_id": "m02"}
POISONED_EMAIL = {"email_id": "m13"}


@pytest.fixture
def poisoned_mail(tmp_path: Path) -> Iterator[ServerThread]:
    server = mail_server.create_server(tmp_path / "mail.db", poisoned=True)
    thread = ServerThread(server.streamable_http_app()).start()
    yield thread
    thread.stop()


def mail_upstream(poisoned_mail: ServerThread) -> UpstreamConfig:
    return UpstreamConfig(
        id="mail", tenant="acme", url=f"{poisoned_mail.url}/mcp", tools=demo_tools("mail")
    )


def code_of(result: Any) -> str:
    assert result.is_error and result.meta is not None, texts(result)
    return str(result.meta["keystone/code"])


def sent_mail(demo: DemoUpstreams) -> list[dict[str, Any]]:
    mails: list[dict[str, Any]] = demo.state("mail")["sent"]  # type: ignore[assignment]
    return mails


async def test_untrusted_and_sensitive_then_external_requires_approval(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    approver: Approver,
) -> None:
    app = keystone_app_factory()

    async with mcp_client(app, user="olivia") as fresh:
        # A session that has read nothing sends a mail to a colleague at once.
        sent = await fresh.call_tool("mail__send_email", INTERNAL)
    async with mcp_client(app, user="olivia") as reader:
        await reader.call_tool("mail__read_email", BENIGN_EMAIL)
        # The same mail, after reading one: the session has now seen untrusted and sensitive data,
        # and the call to send is held for a person.
        held = await reader.call_tool("mail__send_email", INTERNAL)

        assert not sent.is_error
        assert code_of(held) == "KS_APPROVAL_PENDING"
        [request] = await approver.pending()
        assert request.tool_name == "mail__send_email"
        assert list(request.reasons) == ["rule-of-two"]
        assert len(sent_mail(demo_upstreams)) == 1  # only the first mail went out
        # A person says yes, and the mail goes out then.
        await approver.approve("a colleague, and I wrote it")
        done = await reader.call_tool(AWAIT, {"approval_id": request.id, "wait_seconds": 10})

    assert not done.is_error, texts(done)
    assert [mail["to"] for mail in sent_mail(demo_upstreams)] == ["colleague@acme.test"] * 2


async def test_tainted_external_effect_requires_approval(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    approver: Approver,
) -> None:
    app = keystone_app_factory()

    async with mcp_client(app, user="olivia") as client:
        # echo has no tag, so the session reads an injection and no flag is set: the rule that
        # asks is the taint's, and the two flags' rule has nothing to say.
        echoed = await client.call_tool("echo__echo", {"payload": INJECTION})
        state = one(await client.call_tool(WHOAMI, {}))
        held = await client.call_tool("mail__send_email", INTERNAL)

    assert not echoed.is_error
    assert (state["tainted"], state["flags"]) == (True, [])
    assert code_of(held) == "KS_APPROVAL_PENDING"
    [request] = await approver.pending()
    assert list(request.reasons) == ["tainted-external-effect"]
    assert sent_mail(demo_upstreams) == []


async def test_tainted_critical_denied(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    poisoned_mail: ServerThread,
) -> None:
    # The echo tool is critical in this app, and root is an admin, who may run critical tools.
    echo = UpstreamConfig(
        id="echo",
        tenant="acme",
        url=demo_upstreams.url("echo"),
        tools={"echo": ToolOverride(risk=Risk.CRITICAL)},
    )
    app = keystone_app_factory(settings={"upstreams": [mail_upstream(poisoned_mail), echo]})

    async with mcp_client(app, user="root") as root:
        clean = await root.call_tool("echo__echo", {"payload": "hello"})
        await root.call_tool("mail__read_email", POISONED_EMAIL)  # an injection taints the session
        state = one(await root.call_tool(WHOAMI, {}))
        denied = await root.call_tool("echo__echo", {"payload": "hello again"})

    assert not clean.is_error and texts(clean) == ["hello"]
    assert state["tainted"] is True
    assert code_of(denied) == "KS_DENIED"
    assert denied.meta is not None and denied.meta["keystone/reasons"] == [
        "deny-critical-when-tainted"
    ]
    # Only the first call reached the upstream.
    assert demo_upstreams.state("echo")["calls"] == ["echo"]
    rows = [r for r in app.audit.records if r["tool_name"] == "echo__echo"]
    assert [(r["effect"], r["reasons"], r["dispatched"]) for r in rows] == [
        ("allow", ["admins-critical"], True),
        ("deny", ["deny-critical-when-tainted"], False),
    ]


async def test_a_session_that_read_nothing_untrusted_is_not_asked(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
) -> None:
    app = keystone_app_factory()

    async with mcp_client(app, user="olivia") as client:
        balance = await client.call_tool("bank__get_balance", {"account": "CHK-001"})  # sensitive
        sent = await client.call_tool("mail__send_email", INTERNAL)

    # Sensitive data alone is the second of the two, and the mail goes out without a person.
    assert not balance.is_error and not sent.is_error
    assert len(sent_mail(demo_upstreams)) == 1


async def test_the_reasons_of_the_poisoned_email_are_all_three(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    poisoned_mail: ServerThread,
    approver: Approver,
) -> None:
    app = keystone_app_factory(settings={"upstreams": [mail_upstream(poisoned_mail)]})
    attack = {"to": "attacker@evil.test", "subject": "Invoice 4471", "body": "Pay BIZ-003"}

    async with mcp_client(app, user="olivia") as client:
        await client.call_tool("mail__read_email", POISONED_EMAIL)
        held = await client.call_tool("mail__send_email", attack)

    assert code_of(held) == "KS_APPROVAL_PENDING"
    [request] = await approver.pending()
    # Acme's own rule for mail to other domains, and the two of the Rule of Two.
    assert sorted(request.reasons) == [
        "external-email-needs-approval",
        "rule-of-two",
        "tainted-external-effect",
    ]


async def test_a_taint_recorded_while_an_approval_waits_is_seen_when_the_call_runs(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    demo_upstreams: DemoUpstreams,
    poisoned_mail: ServerThread,
    approver: Approver,
    tmp_path: Path,
) -> None:
    """The await tool holds a call for up to two minutes, and the session can be tainted by
    another call in that time. The call it then runs is decided on the session as it is now: an
    approval for a critical tool, given before the taint, does not run the tool after it."""
    root_dir = copy_pack(tmp_path)
    write_policies(
        root_dir,
        {
            "acme/approval/critical-needs-a-person.cedar": (
                '@id("critical-needs-a-person")\n'
                'permit (principal, action == Keystone::Action::"call_tool", resource)\n'
                "when { resource.risk_level == 4 };\n"
            )
        },
    )
    echo = UpstreamConfig(
        id="echo",
        tenant="acme",
        url=demo_upstreams.url("echo"),
        tools={"echo": ToolOverride(risk=Risk.CRITICAL)},
    )
    app = keystone_app_factory(
        settings={
            "upstreams": [mail_upstream(poisoned_mail), echo],
            "policy": PolicySettings(root=root_dir, include_demo=True),
            "approvals": ApprovalSettings(wait_seconds=1.0, poll_interval_s=0.2),
        }
    )
    answers: dict[str, Any] = {}

    async with mcp_client(app, user="root") as root:
        asked = await root.call_tool("echo__echo", {"payload": "wipe"})
        assert code_of(asked) == "KS_APPROVAL_PENDING"
        approval_id = str(asked.meta["keystone/approval_id"])  # type: ignore[index]

        async def wait_for_the_person() -> None:
            answers["await"] = await root.call_tool(
                AWAIT, {"approval_id": approval_id, "wait_seconds": 30}
            )

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(wait_for_the_person)
            await anyio.sleep(1.0)  # the await call has read the session and is waiting
            # Another call of the session reads the poisoned email while it waits.
            await root.call_tool("mail__read_email", POISONED_EMAIL)
            await approver.approve("the person looked before the taint")

    assert code_of(answers["await"]) == "KS_DENIED"
    assert answers["await"].meta["keystone/reasons"] == ["deny-critical-when-tainted"]
    assert demo_upstreams.state("echo")["calls"] == []
