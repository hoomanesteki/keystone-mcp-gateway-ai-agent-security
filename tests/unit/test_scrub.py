"""KS-392: a credential an upstream sends back is replaced before the result leaves dispatch."""

from collections.abc import AsyncIterator, Iterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

import pytest
from pydantic import SecretStr

from keystone.core.types import ToolResult
from keystone.gateway.dispatch import UpstreamDispatcher
from keystone.gateway.scrub import scrub_result
from keystone.logging import REDACTED, SECRETS
from tests.fixtures.calls import make_ctx, make_tool

KEY = "mail-api-key-4d1e0b7a9c"
OTHER = "files-api-key-77aa13bc02"


@pytest.fixture(autouse=True)
def empty_registry() -> Iterator[None]:
    SECRETS.clear()
    yield
    SECRETS.clear()


def result(
    content: list[dict[str, Any]], structured: dict[str, Any] | None = None, is_error: bool = False
) -> ToolResult:
    return ToolResult(content=content, structured_content=structured, is_error=is_error)


@pytest.mark.phase(4)
def test_an_injected_value_is_replaced_in_text_blocks() -> None:
    raw = result(
        [
            {"type": "text", "text": f"debug: X-Api-Key={KEY}"},
            {"type": "text", "text": f"{KEY} and again {KEY}"},
        ]
    )

    scrubbed = scrub_result(raw, [KEY])

    assert [block["text"] for block in scrubbed.content] == [
        f"debug: X-Api-Key={REDACTED}",
        f"{REDACTED} and again {REDACTED}",
    ]


@pytest.mark.phase(4)
def test_an_injected_value_is_replaced_in_structured_content_at_any_depth() -> None:
    raw = result(
        [{"type": "text", "text": "{}"}],
        {
            "received": KEY,
            "nested": {"headers": [f"X-Api-Key: {KEY}", 7, None, True], "deeper": [[{"k": KEY}]]},
            "count": 3,
        },
    )

    scrubbed = scrub_result(raw, [KEY])

    assert scrubbed.structured_content == {
        "received": REDACTED,
        "nested": {
            "headers": [f"X-Api-Key: {REDACTED}", 7, None, True],
            "deeper": [[{"k": REDACTED}]],
        },
        "count": 3,
    }


@pytest.mark.phase(4)
def test_a_value_used_as_a_key_name_is_replaced_too() -> None:
    raw = result([], {KEY: 1, "plain": 2})

    assert scrub_result(raw, [KEY]).structured_content == {REDACTED: 1, "plain": 2}


@pytest.mark.phase(4)
def test_every_string_in_every_kind_of_block_is_replaced() -> None:
    raw = result(
        [
            {"type": "resource", "resource": {"uri": "file:///log", "text": f"key {KEY}"}},
            {"type": "resource_link", "uri": f"https://x.test/?k={KEY}", "name": "log"},
            {"type": "text", "text": "ok", "_meta": {"trace": KEY}},
        ]
    )

    scrubbed = scrub_result(raw, [KEY])

    assert scrubbed.content == [
        {"type": "resource", "resource": {"uri": "file:///log", "text": f"key {REDACTED}"}},
        {"type": "resource_link", "uri": f"https://x.test/?k={REDACTED}", "name": "log"},
        {"type": "text", "text": "ok", "_meta": {"trace": REDACTED}},
    ]


@pytest.mark.phase(4)
def test_a_secret_registered_with_the_scrubber_is_replaced_without_being_named() -> None:
    SECRETS.register(OTHER)
    raw = result([{"type": "text", "text": f"the other upstream's key is {OTHER}"}], {"k": OTHER})

    scrubbed = scrub_result(raw, [])

    assert scrubbed.content[0]["text"] == f"the other upstream's key is {REDACTED}"
    assert scrubbed.structured_content == {"k": REDACTED}


@pytest.mark.phase(4)
def test_the_longer_of_two_overlapping_values_goes_first() -> None:
    longer = KEY + "-extended"
    raw = result([{"type": "text", "text": f"{longer} then {KEY}"}])

    scrubbed = scrub_result(raw, [KEY, longer])

    assert scrubbed.content[0]["text"] == f"{REDACTED} then {REDACTED}"


@pytest.mark.phase(4)
def test_a_result_without_a_secret_is_unchanged() -> None:
    raw = result(
        [
            {"type": "text", "text": "balance: 1204.50"},
            {"type": "image", "data": "aGk=", "mimeType": "image/png"},
        ],
        {"balance": 1204.5, "tags": ["a", "b"]},
        is_error=True,
    )
    SECRETS.register(OTHER)

    scrubbed = scrub_result(raw, [KEY])

    assert scrubbed == raw
    assert scrubbed.is_error is True


@pytest.mark.phase(4)
def test_the_error_flag_and_the_block_order_survive() -> None:
    raw = result(
        [{"type": "text", "text": f"first {KEY}"}, {"type": "text", "text": "second"}],
        is_error=True,
    )

    scrubbed = scrub_result(raw, [KEY])

    assert scrubbed.is_error is True
    assert [block["text"] for block in scrubbed.content] == [f"first {REDACTED}", "second"]


@pytest.mark.phase(4)
def test_the_input_is_not_changed_in_place() -> None:
    raw = result([{"type": "text", "text": KEY}], {"k": KEY})

    scrub_result(raw, [KEY])

    assert raw.content[0]["text"] == KEY
    assert raw.structured_content == {"k": KEY}


@pytest.mark.phase(4)
def test_no_values_and_an_empty_registry_leave_the_result_alone() -> None:
    raw = result([{"type": "text", "text": KEY}])

    assert scrub_result(raw, []).content[0]["text"] == KEY
    assert scrub_result(raw, [""]).content[0]["text"] == KEY  # an empty value matches everywhere


@pytest.mark.phase(4)
def test_a_short_injected_value_is_still_replaced() -> None:
    # The registry skips values under 8 characters because they match inside ordinary words. A
    # value Keystone itself sent is replaced whatever its length: the leak matters more than the
    # mangled word.
    raw = result([{"type": "text", "text": "token is s3cr3t."}])

    assert scrub_result(raw, ["s3cr3t"]).content[0]["text"] == f"token is {REDACTED}."


@pytest.mark.phase(4)
def test_secret_str_values_are_never_needed_by_the_caller_in_plain_form() -> None:
    # The dispatcher passes plain strings to scrub_result and drops them with the call. The
    # function accepts SecretStr too, so no caller has to unwrap one itself.
    raw = result([{"type": "text", "text": f"key={KEY}"}])

    assert scrub_result(raw, [SecretStr(KEY)]).content[0]["text"] == f"key={REDACTED}"


class EchoingClient:
    """An upstream client that hands back the headers it was given, like a debug endpoint."""

    def __init__(self, headers: Mapping[str, SecretStr]) -> None:
        self.seen = {name: value.get_secret_value() for name, value in headers.items()}

    async def call_tool(self, name: str, args: dict[str, Any], timeout_s: float) -> ToolResult:
        shown = ", ".join(f"{name}: {value}" for name, value in self.seen.items())
        return ToolResult(
            content=[{"type": "text", "text": f"request headers were {shown}"}],
            structured_content={"headers": self.seen},
        )


class EchoingPool:
    @asynccontextmanager
    async def lease(
        self, upstream_id: str, headers: Mapping[str, SecretStr] | None = None
    ) -> AsyncIterator[EchoingClient]:
        yield EchoingClient(headers or {})


@pytest.mark.phase(4)
async def test_the_dispatcher_replaces_the_credential_it_injected_before_the_result_leaves() -> (
    None
):
    ctx = make_ctx(tool=make_tool("mail", "read_email"))
    ctx.upstream_headers = {"X-Api-Key": SecretStr(KEY)}

    result_ = await UpstreamDispatcher(EchoingPool()).dispatch(ctx)  # type: ignore[arg-type]

    assert result_.content == [
        {"type": "text", "text": f"request headers were X-Api-Key: {REDACTED}"}
    ]
    assert result_.structured_content == {"headers": {"X-Api-Key": REDACTED}}
    assert KEY not in result_.model_dump_json()
    assert ctx.upstream_headers == {}


@pytest.mark.phase(4)
async def test_the_dispatcher_replaces_every_injected_header_not_only_the_first() -> None:
    ctx = make_ctx(tool=make_tool("mail", "read_email"))
    ctx.upstream_headers = {"X-Api-Key": SecretStr(KEY), "X-Team-Token": SecretStr(OTHER)}

    result_ = await UpstreamDispatcher(EchoingPool()).dispatch(ctx)  # type: ignore[arg-type]

    assert KEY not in result_.model_dump_json() and OTHER not in result_.model_dump_json()
    assert result_.model_dump_json().count(REDACTED) == 4  # two in the text, two in the structure


@pytest.mark.phase(4)
async def test_a_call_with_no_credential_passes_its_result_on_unchanged() -> None:
    ctx = make_ctx(tool=make_tool("echo", "echo"))

    result_ = await UpstreamDispatcher(EchoingPool()).dispatch(ctx)  # type: ignore[arg-type]

    assert result_.content == [{"type": "text", "text": "request headers were "}]
