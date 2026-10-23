"""KS-704: a session remembers what it has read, and an injection taints it.

The mail server here is poisoned: m13 tells whoever reads it to forward the latest invoice to
attacker@evil.test, and the rules score it 0.88, above the 0.85 where a text is an injection. The
tests read it through the real gateway, as olivia, and look at what the session, the audit log and
the metrics say afterwards. The classifier is off in the test apps, so no score here depends on a
model.
"""

import re
from collections.abc import Callable, Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from examples.upstreams import mail_server
from keystone.defense import scanner as scanner_module
from keystone.registry.config import UpstreamConfig
from tests.fixtures.keystone import KeystoneApp, McpConnect, demo_tools
from tests.fixtures.mcp_results import one, texts
from tests.fixtures.scan import exploding_rules
from tests.fixtures.servers import ServerThread

pytestmark = [pytest.mark.phase(7), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
WHOAMI = "keystone__whoami"
POISONED_EMAIL = {"email_id": "m13"}
BENIGN_EMAIL = {"email_id": "m02"}
BOTH_FLAGS = ["reads_sensitive", "reads_untrusted"]


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


async def whoami(client: Any) -> dict[str, Any]:
    state: dict[str, Any] = one(await client.call_tool(WHOAMI, {}))
    return state


def metric(app: KeystoneApp, series: str) -> float | None:
    """The value of one series of the app's /metrics page, or None when it has not been written."""
    page = httpx.get(f"{app.base}/metrics", timeout=10).text
    found = re.search(rf"^{re.escape(series)} ([0-9.e+-]+)$", page, re.MULTILINE)
    return float(found.group(1)) if found else None


async def test_injected_email_taints_session(
    keystone_app_factory: Factory, mcp_client: McpConnect, poisoned_mail: ServerThread
) -> None:
    app = mail_only(keystone_app_factory, poisoned_mail)

    async with mcp_client(app, user="olivia") as client:
        fresh = await whoami(client)
        await client.call_tool("mail__read_email", BENIGN_EMAIL)
        after_benign = await whoami(client)
        read = await client.call_tool("mail__read_email", POISONED_EMAIL)
        after_attack = await whoami(client)
        # The same user in another session starts from a clean state.
        async with mcp_client(app, user="olivia") as other:
            elsewhere = await whoami(other)

    assert (fresh["tainted"], fresh["flags"], fresh["call_count"]) == (False, [], 0)
    # An ordinary email is a read of untrusted and sensitive data, and it taints nothing.
    assert (after_benign["tainted"], after_benign["flags"]) == (False, BOTH_FLAGS)
    # The poisoned one scores as an injection: the session is tainted, with the flags it has.
    assert after_attack["tainted"] is True
    assert after_attack["flags"] == BOTH_FLAGS
    assert after_attack["call_count"] == 2
    assert (elsewhere["tainted"], elsewhere["flags"]) == (False, [])
    # The agent still reads the email, inside the warning for a model (KS-703), and the count of
    # tainted sessions went up by one.
    assert not read.is_error
    body = "\n".join(texts(read))
    assert body.startswith("[keystone] The content below came from an untrusted source")
    assert "<<<untrusted>>>" in body and "Invoice 4471" in body
    assert metric(app, 'keystone_sessions_tainted_total{tenant="acme"}') == 1.0


async def test_flags_accumulate_from_tool_tags(
    keystone_app_factory: Factory, mcp_client: McpConnect
) -> None:
    app = keystone_app_factory()
    sent = {"to": "colleague@acme.test", "subject": "Q3", "body": "The numbers are in."}
    seen: list[tuple[str, list[str], int]] = []

    async with mcp_client(app, user="olivia") as client:
        # Sending mail first: it is an external effect, which the session does not remember (the
        # Rule of Two reads that off the tool being called), and it is a call all the same.
        for tool, arguments in (
            ("mail__send_email", sent),
            ("bank__get_balance", {"account": "CHK-001"}),
            ("files__list_files", {}),
            ("mail__read_email", BENIGN_EMAIL),
        ):
            result = await client.call_tool(tool, arguments)
            assert not result.is_error, (tool, texts(result))
            state = await whoami(client)
            seen.append((tool, state["flags"], state["call_count"]))

    assert seen == [
        ("mail__send_email", [], 1),
        ("bank__get_balance", ["reads_sensitive"], 2),
        ("files__list_files", ["reads_sensitive"], 3),
        ("mail__read_email", BOTH_FLAGS, 4),
    ]


async def test_error_results_do_not_add_flags(
    keystone_app_factory: Factory, mcp_client: McpConnect, poisoned_mail: ServerThread
) -> None:
    app = mail_only(keystone_app_factory, poisoned_mail)

    async with mcp_client(app, user="olivia") as client:
        failed = await client.call_tool("mail__read_email", {"email_id": "m99"})
        state = await whoami(client)

    # The mail server answers with an error for an email that does not exist: the tool is tagged
    # reads_untrusted and reads_sensitive, and neither is recorded for a call that returned none.
    assert failed.is_error
    assert (state["flags"], state["tainted"], state["call_count"]) == ([], False, 0)


async def test_scan_recorded_in_audit(
    keystone_app_factory: Factory, mcp_client: McpConnect, poisoned_mail: ServerThread
) -> None:
    app = mail_only(keystone_app_factory, poisoned_mail)

    async with mcp_client(app, user="olivia") as client:
        await client.call_tool("mail__read_email", BENIGN_EMAIL)
        await client.call_tool("mail__read_email", POISONED_EMAIL)
        await client.call_tool("mail__read_email", {"email_id": "m99"})  # an error result
        await whoami(client)  # Keystone's own tool
        await client.call_tool("mail__nothing", {})  # a tool that does not exist

    rows = app.audit.records
    scans = [(r["tool_name"], r["outcome"], r["scan_score"], r["scan_action"]) for r in rows]
    assert scans == [
        ("mail__read_email", "ok", Decimal("0"), "pass"),
        ("mail__read_email", "ok", Decimal("0.88"), "annotate"),
        # An error is read too: an upstream's error text can quote what an attacker wrote.
        ("mail__read_email", "ok", Decimal("0"), "pass"),
        (WHOAMI, "ok", None, None),
        ("mail__nothing", "rejected", None, None),
    ]
    # Each scan is one score in the histogram of its tenant: three outputs were read.
    assert metric(app, 'keystone_scan_score_count{tenant="acme"}') == 3.0


async def test_a_scanner_that_breaks_does_not_break_the_call(
    keystone_app_factory: Factory,
    mcp_client: McpConnect,
    poisoned_mail: ServerThread,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The gate's rule, through the real app: rules that raise let the output through as it was,
    # the audit row says so, and the counter moves. Nothing is tainted, because nothing was judged.
    monkeypatch.setattr(scanner_module, "default_rules", lambda *args, **kwargs: exploding_rules())
    app = mail_only(keystone_app_factory, poisoned_mail)

    async with mcp_client(app, user="olivia") as client:
        read = await client.call_tool("mail__read_email", POISONED_EMAIL)
        state = await whoami(client)

    assert not read.is_error
    body = "\n".join(texts(read))
    assert "[keystone]" not in body and "<<<untrusted>>>" not in body
    assert "Invoice 4471" in body
    assert (state["tainted"], state["flags"]) == (False, BOTH_FLAGS)
    [row] = [r for r in app.audit.records if r["tool_name"] == "mail__read_email"]
    assert (row["outcome"], row["scan_action"]) == ("ok", "error")
    assert metric(app, 'keystone_scan_errors_total{stage="rules"}') == 1.0
