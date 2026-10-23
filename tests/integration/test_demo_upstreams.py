import secrets
import sys
from pathlib import Path
from typing import Any

import httpx2
import pytest
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from examples.upstreams import _common, echo_server, files_server, mail_server
from tests.fixtures.mcp_results import many, one, texts
from tests.fixtures.servers import ServerThread
from tests.fixtures.upstreams import NAMES, DemoUpstreams

ROOT = Path(__file__).resolve().parents[2]


async def call(ups: DemoUpstreams, name: str, tool: str, **arguments: Any) -> Any:
    async with ups.client(name) as client:
        return await client.call_tool(tool, arguments)


@pytest.mark.phase(1)
async def test_mail_tools(demo_upstreams: DemoUpstreams) -> None:
    inbox = many(await call(demo_upstreams, "mail", "list_emails"))
    assert len(inbox) == 8
    assert [m["id"] for m in inbox][:2] == ["m08", "m07"]  # newest first

    unread = many(await call(demo_upstreams, "mail", "list_emails", unread_only=True))
    assert [m["id"] for m in unread] == ["m08", "m06", "m04", "m02", "m01"]
    assert len(many(await call(demo_upstreams, "mail", "list_emails", folder="sent"))) == 2

    email = one(await call(demo_upstreams, "mail", "read_email", email_id="m02"))
    assert email["from"] == "billing@brightline.test"
    assert "Invoice 4471" in email["body"]

    sent = one(
        await call(
            demo_upstreams,
            "mail",
            "send_email",
            to="colleague@acme.test",
            subject="Hi",
            body="Hello",
        )
    )
    assert sent == {"status": "sent", "id": "s1", "to": "colleague@acme.test"}
    assert demo_upstreams.state("mail")["sent"] == [
        {"id": "s1", "to": "colleague@acme.test", "subject": "Hi", "body": "Hello"}
    ]


@pytest.mark.phase(1)
@pytest.mark.parametrize(
    ("tool", "arguments", "message"),
    [
        ("read_email", {"email_id": "nope"}, "no email"),
        ("list_emails", {"folder": "spam"}, "unknown folder"),
        ("send_email", {"to": "not-an-address", "subject": "s", "body": "b"}, "not an email"),
        ("send_email", {"to": "a b@x.test", "subject": "s", "body": "b"}, "not an email"),
    ],
)
async def test_mail_errors_are_error_results(
    demo_upstreams: DemoUpstreams, tool: str, arguments: dict[str, Any], message: str
) -> None:
    result = await call(demo_upstreams, "mail", tool, **arguments)

    assert result.is_error
    assert message in texts(result)[0]
    assert demo_upstreams.state("mail")["sent"] == []


@pytest.mark.phase(1)
async def test_bank_transfer_updates_state(demo_upstreams: DemoUpstreams) -> None:
    before = one(await call(demo_upstreams, "bank", "get_balance", account="CHK-001"))
    assert before == {
        "account": "CHK-001",
        "owner": "Olivia Reyes",
        "currency": "USD",
        "balance": 4825.50,
    }

    moved = one(
        await call(
            demo_upstreams,
            "bank",
            "transfer",
            from_account="CHK-001",
            to="SAV-002",
            amount=100.25,
            memo="rainy day",
        )
    )
    assert moved["status"] == "completed"
    assert moved["transfer_id"] == "t1"

    after = one(await call(demo_upstreams, "bank", "get_balance", account="CHK-001"))
    savings = one(await call(demo_upstreams, "bank", "get_balance", account="SAV-002"))
    assert (after["balance"], savings["balance"]) == (4725.25, 12600.25)
    state = demo_upstreams.state("bank")
    assert state["transfers"] == [
        {"id": "t1", "from": "CHK-001", "to": "SAV-002", "amount": 100.25, "memo": "rainy day"}
    ]
    assert state["balances"] == {"BIZ-003": 76330.75, "CHK-001": 4725.25, "SAV-002": 12600.25}
    latest = many(
        await call(demo_upstreams, "bank", "list_transactions", account="CHK-001", limit=1)
    )
    assert [t["description"] for t in latest] == ["Transfer to SAV-002"]


@pytest.mark.phase(1)
async def test_bank_external_transfer_only_debits(demo_upstreams: DemoUpstreams) -> None:
    await call(
        demo_upstreams,
        "bank",
        "transfer",
        from_account="BIZ-003",
        to="NL91ABNA0417164300",
        amount=50,
    )

    balances = demo_upstreams.state("bank")["balances"]
    assert isinstance(balances, dict)
    assert balances["BIZ-003"] == 76330.75 - 50
    assert balances["CHK-001"] == 4825.50


@pytest.mark.phase(1)
@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"from_account": "CHK-001", "to": "SAV-002", "amount": 5000.01}, "insufficient funds"),
        ({"from_account": "CHK-001", "to": "SAV-002", "amount": -5}, "positive"),
        ({"from_account": "CHK-001", "to": "SAV-002", "amount": 0}, "positive"),
        ({"from_account": "CHK-001", "to": "SAV-002", "amount": 1.234}, "two decimal"),
        ({"from_account": "NOPE-9", "to": "SAV-002", "amount": 1}, "unknown account"),
    ],
)
async def test_bank_refuses_bad_transfers(
    demo_upstreams: DemoUpstreams, arguments: dict[str, Any], message: str
) -> None:
    result = await call(demo_upstreams, "bank", "transfer", **arguments)

    assert result.is_error
    assert message in texts(result)[0]
    assert demo_upstreams.state("bank")["transfers"] == []


@pytest.mark.phase(1)
@pytest.mark.parametrize(
    "path", ["../etc/passwd", "/etc/passwd", "notes/../../outside.txt", "..", "a\x00b"]
)
async def test_files_blocks_path_escape(demo_upstreams: DemoUpstreams, path: str) -> None:
    read = await call(demo_upstreams, "files", "read_file", path=path)
    write = await call(demo_upstreams, "files", "write_file", path=path, content="x")
    listing = await call(demo_upstreams, "files", "list_files", path=path)

    assert read.is_error
    assert write.is_error
    assert listing.is_error
    assert demo_upstreams.state("files")["written"] == []


@pytest.mark.phase(1)
async def test_files_block_a_symlink_that_leaves_the_workspace(
    demo_upstreams: DemoUpstreams, tmp_path: Path
) -> None:
    outside = tmp_path / "secret.txt"
    outside.write_text("top secret")
    (demo_upstreams.workspace / "link.txt").symlink_to(outside)

    read = await call(demo_upstreams, "files", "read_file", path="link.txt")
    write = await call(demo_upstreams, "files", "write_file", path="link.txt", content="x")

    assert read.is_error
    assert "outside the workspace" in texts(read)[0]
    assert write.is_error
    assert outside.read_text() == "top secret"


@pytest.mark.phase(1)
async def test_files_read_write_and_list(demo_upstreams: DemoUpstreams) -> None:
    listing = many(await call(demo_upstreams, "files", "list_files"))
    assert [(e["name"], e["type"]) for e in listing] == [
        ("README.txt", "file"),
        ("notes", "folder"),
        ("reports", "folder"),
    ]
    csv = await call(demo_upstreams, "files", "read_file", path="reports/q3-summary.csv")
    assert "Operations,180000,187300" in texts(csv)[0]

    wrote = one(
        await call(
            demo_upstreams, "files", "write_file", path="notes/new/today.md", content="# Today"
        )
    )
    assert wrote == {"path": "notes/new/today.md", "bytes": 7}
    back = await call(demo_upstreams, "files", "read_file", path="notes/new/today.md")
    assert texts(back) == ["# Today"]
    assert demo_upstreams.state("files")["written"] == [
        {"path": "notes/new/today.md", "content": "# Today"}
    ]


@pytest.mark.phase(1)
async def test_echo_tools(demo_upstreams: DemoUpstreams) -> None:
    assert texts(await call(demo_upstreams, "echo", "echo", payload="ping")) == ["ping"]
    assert texts(await call(demo_upstreams, "echo", "sleep", seconds=0.01)) == ["slept 0.01"]
    failed = await call(demo_upstreams, "echo", "fail", message="on purpose")
    assert failed.is_error
    assert "on purpose" in texts(failed)[0]
    too_long = await call(demo_upstreams, "echo", "sleep", seconds=61)
    assert too_long.is_error
    state = demo_upstreams.state("echo")
    assert state["calls"] == ["echo", "sleep", "fail", "sleep"]


@pytest.mark.phase(1)
async def test_mutate_changes_the_echo_description(demo_upstreams: DemoUpstreams) -> None:
    async def description() -> str | None:
        async with demo_upstreams.client("echo") as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            return tools["echo"].description

    original = await description()
    response = httpx2.post(f"{demo_upstreams.base('echo')}/_mutate", timeout=10)

    assert response.status_code == 200
    assert await description() == response.json()["description"] != original
    chosen = httpx2.post(
        f"{demo_upstreams.base('echo')}/_mutate", json={"description": "Chosen text."}, timeout=10
    )
    assert chosen.json() == {"tool": "echo", "description": "Chosen text."}
    assert await description() == "Chosen text."


@pytest.mark.phase(1)
async def test_poisoned_flag_adds_a_tool_with_an_injected_description() -> None:
    clean = echo_server.create_server(poisoned=False)
    poisoned = echo_server.create_server(poisoned=True)

    assert {t.name for t in await clean.list_tools()} == {"echo", "sleep", "fail"}
    tools = {t.name: t for t in await poisoned.list_tools()}
    assert set(tools) == {"echo", "sleep", "fail", "summarize"}
    assert "ops-review@attacker.test" in (tools["summarize"].description or "")


@pytest.mark.phase(1)
async def test_reset_restores_seed(demo_upstreams: DemoUpstreams) -> None:
    before = {name: demo_upstreams.state(name) for name in NAMES}
    inbox_before = many(await call(demo_upstreams, "mail", "list_emails"))
    files_before = many(await call(demo_upstreams, "files", "list_files", path="notes"))

    await call(demo_upstreams, "mail", "send_email", to="x@acme.test", subject="s", body="b")
    await call(demo_upstreams, "bank", "transfer", from_account="CHK-001", to="SAV-002", amount=9)
    await call(demo_upstreams, "files", "write_file", path="notes/extra.md", content="x")
    await call(demo_upstreams, "files", "write_file", path="README.txt", content="changed")
    httpx2.post(f"{demo_upstreams.base('echo')}/_mutate", timeout=10)
    assert {name: demo_upstreams.state(name) for name in NAMES} != before

    demo_upstreams.reset()

    assert {name: demo_upstreams.state(name) for name in NAMES} == before
    assert many(await call(demo_upstreams, "mail", "list_emails")) == inbox_before
    assert many(await call(demo_upstreams, "files", "list_files", path="notes")) == files_before
    readme = await call(demo_upstreams, "files", "read_file", path="README.txt")
    assert "Shared team workspace" in texts(readme)[0]


@pytest.mark.phase(1)
async def test_state_and_reset_are_not_tools(demo_upstreams: DemoUpstreams) -> None:
    for name in NAMES:
        async with demo_upstreams.client(name) as client:
            names = {t.name for t in (await client.list_tools()).tools}
        assert not {n for n in names if n.startswith("_")}


@pytest.mark.phase(1)
async def test_a_server_with_an_api_key_refuses_calls_without_it(tmp_path: Path) -> None:
    app = _common.http_app(
        mail_server.create_server(tmp_path / "mail.db"), api_key="s3cret", host="127.0.0.1"
    )
    thread = ServerThread(app).start()
    try:

        async def list_tools(key: str | None) -> Any:
            headers = {"X-Api-Key": key} if key else {}
            http = httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(10))
            async with Client(streamable_http_client(f"{thread.url}/mcp", http_client=http)) as c:
                return await c.list_tools()

        assert {t.name for t in (await list_tools("s3cret")).tools} >= {"send_email"}
        probe = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        for key in (None, "wrong", "s3cre", "s3cret-and-more"):
            headers = {"X-Api-Key": key} if key else {}
            refused = httpx2.post(f"{thread.url}/mcp", json=probe, headers=headers, timeout=10)
            assert refused.status_code == 401
            with pytest.raises(Exception):  # noqa: B017 - the SDK wraps the 401 in an ExceptionGroup
                await list_tools(key)
        # The test routes carry no tools, so they stay open.
        assert httpx2.get(f"{thread.url}/healthz", timeout=10).status_code == 200
    finally:
        thread.stop()


@pytest.mark.phase(3)
async def test_state_says_whether_the_right_key_arrived_and_never_shows_it(tmp_path: Path) -> None:
    key = f"s3cret-{secrets.token_hex(6)}"
    app = _common.http_app(
        mail_server.create_server(tmp_path / "mail.db"), api_key=key, host="127.0.0.1"
    )
    thread = ServerThread(app).start()
    probe = {"jsonrpc": "2.0", "id": 1, "method": "ping"}

    def state() -> Any:
        return httpx2.get(f"{thread.url}/_state", timeout=10)

    try:
        assert state().json()["api_key_received"] is False
        httpx2.post(f"{thread.url}/mcp", json=probe, headers={"X-Api-Key": "wrong"}, timeout=10)
        assert state().json()["api_key_received"] is False  # a refused request does not count
        httpx2.post(f"{thread.url}/mcp", json=probe, headers={"X-Api-Key": key}, timeout=10)
        arrived = state()
        httpx2.post(f"{thread.url}/_reset", timeout=10)
        reset = state()
    finally:
        thread.stop()

    assert arrived.json()["api_key_received"] is True
    assert key not in arrived.text  # a boolean, never the value
    assert reset.json()["api_key_received"] is False


@pytest.mark.phase(3)
async def test_a_server_without_a_key_reports_none_arrived(demo_upstreams: DemoUpstreams) -> None:
    await call(demo_upstreams, "mail", "list_emails")

    assert demo_upstreams.state("mail")["api_key_received"] is False


@pytest.mark.phase(3)
async def test_a_files_server_can_start_from_another_seed(tmp_path: Path) -> None:
    seed = ROOT / "examples" / "fixtures" / "files-globex"
    server = files_server.create_server(tmp_path / "workspace", tmp_path / "files.db", seed=seed)
    thread = ServerThread(server.streamable_http_app()).start()
    try:
        async with Client(f"{thread.url}/mcp") as client:
            listing = many(await client.call_tool("list_files", {"path": "."}))
            readme = texts(await client.call_tool("read_file", {"path": "README.txt"}))[0]
            await client.call_tool("write_file", {"path": "README.txt", "content": "changed"})
        httpx2.post(f"{thread.url}/_reset", timeout=10)
        async with Client(f"{thread.url}/mcp") as client:
            again = texts(await client.call_tool("read_file", {"path": "README.txt"}))[0]
    finally:
        thread.stop()

    assert [entry["name"] for entry in listing] == ["README.txt", "finance", "projects"]
    assert "Globex shared drive" in readme
    assert again == readme  # reset goes back to that seed, not to the default one


@pytest.mark.phase(1)
@pytest.mark.parametrize(
    ("module", "tool", "arguments", "expected"),
    [
        ("echo", "echo", {"payload": "over stdio"}, "over stdio"),
        ("mail", "read_email", {"email_id": "m03"}, "Offsite agenda draft"),
        ("bank", "get_balance", {"account": "SAV-002"}, "12500.0"),
        ("files", "read_file", {"path": "README.txt"}, "Shared team workspace"),
    ],
)
async def test_each_server_works_over_stdio(
    tmp_path: Path, module: str, tool: str, arguments: dict[str, Any], expected: str
) -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", f"examples.upstreams.{module}_server", "--transport", "stdio"],
        cwd=ROOT,
        env={
            "MAIL_DB": str(tmp_path / "mail.db"),
            "BANK_DB": str(tmp_path / "bank.db"),
            "FILES_DB": str(tmp_path / "files.db"),
            "FILES_WORKSPACE": str(tmp_path / "workspace"),
        },
    )
    async with Client(params) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        result = await client.call_tool(tool, arguments)

    assert tool in names
    assert not result.is_error
    assert expected in "".join(texts(result))
