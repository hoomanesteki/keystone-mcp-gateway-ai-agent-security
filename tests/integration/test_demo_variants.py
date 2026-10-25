"""KS-901: the demo upstreams load the state of a scenario on `POST /_reset?variant=<name>`.

A variant is a folder of `examples/fixtures/variants/` with a file for each upstream it changes
(`mail.json`, `files/`, `bank.json`, `web.json`), put over the seed. The folder `_base` is put over
first for every variant. A reset with no variant is what it has always been.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import Client

from examples.upstreams import _common, echo_server, mail_server
from tests.fixtures.redteam import RedTeamUpstreams
from tests.fixtures.servers import ServerThread

pytestmark = pytest.mark.phase(9)

VARIANT = "mail_summary-exfil_email"
UPSTREAMS: tuple[Any, ...] = ("mail", "files", "bank", "web")


def reset(upstreams: RedTeamUpstreams, name: Any, variant: str | None) -> httpx.Response:
    params = {"variant": variant} if variant is not None else None
    return httpx.post(f"{upstreams.threads[name].url}/_reset", params=params, timeout=10)


async def result_of(upstreams: RedTeamUpstreams, name: Any, tool: str, **arguments: Any) -> Any:
    async with Client(upstreams.mcp(name)) as client:
        return await client.call_tool(tool, arguments)


def text_of(result: Any) -> str:
    return "\n".join(str(getattr(block, "text", "")) for block in result.content)


async def test_a_variant_puts_the_upstreams_in_the_state_of_a_scenario(
    redteam_upstreams: RedTeamUpstreams,
) -> None:
    redteam_upstreams.reset(VARIANT)

    mail = await result_of(redteam_upstreams, "mail", "read_email", email_id="x01")
    config = await result_of(redteam_upstreams, "files", "read_file", path="config/settings.txt")

    sender = json.loads(text_of(mail))
    assert sender["from"] == "onboarding@northwind.test" and "ks-do" in sender["body"]
    assert text_of(config).startswith("api_endpoint=https://api.acme.test")


async def test_a_reset_without_a_variant_is_the_seed_again(
    redteam_upstreams: RedTeamUpstreams,
) -> None:
    redteam_upstreams.reset(VARIANT)

    answer = reset(redteam_upstreams, "mail", None)
    redteam_upstreams.reset(None)

    assert answer.status_code == 200 and answer.json() == {"status": "reset"}
    gone = await result_of(redteam_upstreams, "mail", "read_email", email_id="x01")
    assert gone.is_error and "no email with id" in text_of(gone)
    absent = await result_of(redteam_upstreams, "files", "read_file", path="config/settings.txt")
    assert absent.is_error and "is not a file" in text_of(absent)


def test_the_answer_names_the_variant(redteam_upstreams: RedTeamUpstreams) -> None:
    answer = reset(redteam_upstreams, "bank", "bank_pay-benign")

    assert answer.status_code == 200
    assert answer.json() == {"status": "reset", "variant": "bank_pay-benign"}


async def test_a_variant_adds_a_transaction_a_page_and_a_file(
    redteam_upstreams: RedTeamUpstreams,
) -> None:
    redteam_upstreams.reset("bank_pay-benign")
    history = await result_of(
        redteam_upstreams, "bank", "list_transactions", account="BIZ-003", limit=3
    )
    redteam_upstreams.reset("web_changelog-benign")
    page = await result_of(
        redteam_upstreams, "web", "fetch", url="https://docs.partner.test/api/changelog"
    )
    redteam_upstreams.reset("files_vendor-benign")
    note = await result_of(
        redteam_upstreams, "files", "read_file", path="notes/vendor-onboarding.md"
    )

    assert "invoice 4470, paid" in text_of(history)
    # The seed's page of the changelog carries an attack, and the variant replaces it.
    assert "100 requests a minute" in text_of(page) and "ks-do" not in text_of(page)
    assert text_of(note).startswith("# Vendor onboarding checklist") and "ks-do" not in text_of(
        note
    )


@pytest.mark.parametrize("bad", ["no-such-variant", "../etc", "a/b", "_base", "UPPER", "x" * 200])
def test_a_variant_that_does_not_exist_is_a_404_and_changes_nothing(
    redteam_upstreams: RedTeamUpstreams, bad: str
) -> None:
    redteam_upstreams.reset(VARIANT)
    before = redteam_upstreams.states()

    for name in UPSTREAMS:
        answer = reset(redteam_upstreams, name, bad)
        assert answer.status_code == 404, (name, bad)
        assert "unknown variant" in answer.json()["error"]

    assert redteam_upstreams.states() == before


async def test_a_wrong_name_leaves_the_mail_of_the_variant_in_place(
    redteam_upstreams: RedTeamUpstreams,
) -> None:
    redteam_upstreams.reset(VARIANT)

    assert reset(redteam_upstreams, "mail", "no-such-variant").status_code == 404

    kept = await result_of(redteam_upstreams, "mail", "read_email", email_id="x01")
    assert not kept.is_error


def test_a_server_with_no_variants_says_so() -> None:
    thread = ServerThread(echo_server.create_server(poisoned=False).streamable_http_app()).start()
    try:
        answer = httpx.post(f"{thread.url}/_reset", params={"variant": VARIANT}, timeout=10)

        assert answer.status_code == 404 and "no variants" in answer.json()["error"]
        assert httpx.post(f"{thread.url}/_reset", timeout=10).status_code == 200
    finally:
        thread.stop()


async def test_a_variant_is_not_poisoned_by_the_flag_of_the_server(tmp_path: Path) -> None:
    server = mail_server.create_server(tmp_path / "mail.db", poisoned=True)
    thread = ServerThread(_common.http_app(server, api_key=None, host="127.0.0.1")).start()
    try:
        async with Client(f"{thread.url}/mcp") as client, httpx.AsyncClient(timeout=10) as http:
            seeded = await client.call_tool("list_emails", {"folder": "inbox"})
            assert "m13" in str(seeded.content)  # the flag adds the poisoned mails to the seed

            await http.post(f"{thread.url}/_reset", params={"variant": "mail_summary-benign"})

            clean = await client.call_tool("list_emails", {"folder": "inbox"})
            assert "m13" not in str(clean.content) and "x01" in str(clean.content)
    finally:
        thread.stop()
