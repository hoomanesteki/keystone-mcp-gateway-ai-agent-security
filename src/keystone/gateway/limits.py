"""Size limits at the edge of /mcp (KS-906).

The pipeline refuses arguments over 1 MiB, but only after the whole request was read and parsed.
This middleware stops a request earlier: headers over 16 KiB in total or 100 in number get a 431,
and a body over 2 MiB gets a 413 before the MCP SDK parses any of it. 2 MiB is the 1 MiB argument
limit plus room for the JSON-RPC envelope and for escaping, which can double the size of text.
"""

from __future__ import annotations

import structlog
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = structlog.get_logger()

MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_HEADER_COUNT = 100


def _refusal(status: int, message: str) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": message}},
        status_code=status,
    )


class RequestLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body: int = MAX_BODY_BYTES,
        max_header_bytes: int = MAX_HEADER_BYTES,
        max_header_count: int = MAX_HEADER_COUNT,
    ) -> None:
        self.app = app
        self.max_body = max_body
        self.max_header_bytes = max_header_bytes
        self.max_header_count = max_header_count

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = scope.get("headers", [])
        if len(headers) > self.max_header_count or (
            sum(len(k) + len(v) for k, v in headers) > self.max_header_bytes
        ):
            log.warning("request_headers_too_large", count=len(headers))
            await _refusal(431, "request headers are too large")(scope, receive, send)
            return
        for key, value in headers:
            if key == b"content-length" and (not value.isdigit() or int(value) > self.max_body):
                await _refusal(413, "request body is too large")(scope, receive, send)
                return
        # A chunked body has no length to look at, so it is read up to the limit and replayed.
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return  # the client left
            body = message.get("body", b"")
            size += len(body)
            if size > self.max_body:
                log.warning("request_body_too_large", limit=self.max_body)
                await _refusal(413, "request body is too large")(scope, receive, send)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break
        replay = [b"".join(chunks)]

        async def replayed() -> Message:
            if replay:
                return {"type": "http.request", "body": replay.pop(), "more_body": False}
            return await receive()

        await self.app(scope, replayed, send)
