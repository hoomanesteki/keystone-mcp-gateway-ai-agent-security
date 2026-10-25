"""KS-906: the size limits at the edge of /mcp and on what an upstream sends back."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from starlette.testclient import TestClient
from starlette.types import Message, Receive, Scope, Send

from keystone.admin.schemas import ApproveChange, DecisionBody
from keystone.app import create_app
from keystone.approvals.service import MAX_NOTE_CHARS, _clean_note
from keystone.core.errors import Code, Reject
from keystone.core.types import ToolResult
from keystone.gateway.dispatch import MAX_RESULT_BLOCKS, UpstreamDispatcher, check_result_size
from keystone.gateway.limits import (
    MAX_BODY_BYTES,
    MAX_HEADER_BYTES,
    MAX_HEADER_COUNT,
    RequestLimitMiddleware,
)
from keystone.settings import Settings
from tests.fixtures.calls import make_ctx, make_tool

pytestmark = pytest.mark.phase(9)


async def echo_body(scope: Scope, receive: Receive, send: Send) -> None:
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body"):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": str(len(body)).encode()})


def client() -> TestClient:
    return TestClient(RequestLimitMiddleware(echo_body))


def test_a_body_at_the_limit_passes_and_one_byte_more_is_refused() -> None:
    http = client()
    assert http.post("/", content=b"x" * MAX_BODY_BYTES).text == str(MAX_BODY_BYTES)
    refused = http.post("/", content=b"x" * (MAX_BODY_BYTES + 1))
    assert refused.status_code == 413


def test_a_chunked_body_is_counted_as_it_arrives() -> None:
    def chunks() -> Any:
        for _ in range(MAX_BODY_BYTES // 65536 + 2):
            yield b"x" * 65536

    assert client().post("/", content=chunks()).status_code == 413


def test_a_content_length_that_is_not_a_number_is_refused() -> None:
    sent: list[Message] = []

    async def run() -> None:
        scope = {"type": "http", "headers": [(b"content-length", b"abc")]}

        async def receive() -> Message:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: Message) -> None:
            sent.append(message)

        await RequestLimitMiddleware(echo_body)(scope, receive, send)

    asyncio.run(run())
    assert sent[0]["status"] == 413


def test_too_many_headers_are_refused() -> None:
    headers = {f"x-h{i}": "1" for i in range(MAX_HEADER_COUNT + 1)}
    assert client().post("/", content=b"{}", headers=headers).status_code == 431


def test_headers_over_the_byte_limit_are_refused() -> None:
    big = {"x-big": "a" * MAX_HEADER_BYTES}
    assert client().post("/", content=b"{}", headers=big).status_code == 431


def test_ordinary_headers_pass() -> None:
    headers = {"authorization": "Bearer " + "a" * 2000, "mcp-session-id": "s" * 64}
    assert client().post("/", content=b"{}", headers=headers).status_code == 200


async def test_the_mcp_route_has_the_limit(settings: Settings) -> None:
    transport = httpx.ASGITransport(app=create_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as http:
        big = await http.post("/mcp", content=b"x" * (MAX_BODY_BYTES + 1))
        many = await http.post("/mcp", content=b"{}", headers={"x-big": "a" * MAX_HEADER_BYTES})
    assert big.status_code == 413
    assert many.status_code == 431


def blocks(count: int) -> ToolResult:
    return ToolResult(content=[{"type": "text", "text": "x"}] * count)


def test_a_result_with_too_many_content_blocks_is_refused() -> None:
    check_result_size(blocks(MAX_RESULT_BLOCKS))
    with pytest.raises(Reject) as refused:
        check_result_size(blocks(MAX_RESULT_BLOCKS + 1))
    assert refused.value.code is Code.UPSTREAM_ERROR


def test_a_result_over_the_byte_limit_is_refused() -> None:
    huge = ToolResult(content=[{"type": "text", "text": "x" * (17 * 1024 * 1024)}])
    with pytest.raises(Reject) as refused:
        check_result_size(huge)
    assert refused.value.code is Code.UPSTREAM_ERROR


class BigPool:
    @asynccontextmanager
    async def lease(self, upstream_id: str, headers: Any) -> AsyncIterator[Any]:
        class Client:
            async def call_tool(self, *args: Any, **kwargs: Any) -> ToolResult:
                return blocks(MAX_RESULT_BLOCKS + 1)

        yield Client()


async def test_the_dispatcher_refuses_an_oversized_result() -> None:
    ctx = make_ctx(tool=make_tool("mail", "read_email"))
    with pytest.raises(Reject) as refused:
        await UpstreamDispatcher(BigPool()).dispatch(ctx)  # type: ignore[arg-type]
    assert refused.value.code is Code.UPSTREAM_ERROR


def test_an_approval_note_is_cut_and_the_api_refuses_a_longer_one() -> None:
    assert len(_clean_note("n" * 5000) or "") == MAX_NOTE_CHARS
    assert ApproveChange(note="n" * MAX_NOTE_CHARS).note is not None
    with pytest.raises(ValidationError):
        ApproveChange(note="n" * (MAX_NOTE_CHARS + 1))
    with pytest.raises(ValidationError):
        DecisionBody(approve=True, note="n" * (MAX_NOTE_CHARS + 1))
