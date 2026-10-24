"""A fake of the two model APIs that Keystone's LLM proxy forwards to (KS-806).

It answers `POST /v1/messages` as Anthropic's Messages API does and `POST /v1/chat/completions` as
OpenAI's chat completions do, whole or as a server-sent-event stream, and it reports token usage in
both. It runs as the compose service `fake-llm` (port 8199) for the smoke script and for demos with
no API key, and the tests start it in a thread. It calls no model: the reply is made of numbered
words.

The numbers are deterministic, so that a test or a person can work out what a request cost:

- input tokens: the words of the system prompt and of every message (at least one)
- output tokens: `max_tokens`, but at most 12; the reply is that many words (`reply1 reply2 ...`)

The model name picks a behavior. It is only ever read from the request, so the proxy and the tests
choose by what they ask for:

| The name contains | What it does |
|---|---|
| `cached` | adds 5 cache-read and 2 cache-write tokens (Anthropic), or 5 cached tokens (OpenAI) |
| `no-usage` | a stream that never says what it used |
| `cut` | a stream that breaks off after two events, with no end |
| `slow` | waits 0.5 s before a whole answer, or 0.15 s before each event of a stream |
| `error-429` | 429 with `retry-after: 7` |
| `error-500` | 500 |
| `error-echo-key` | 401 that repeats the credential it was given, as some real APIs do |

If `FAKE_LLM_API_KEY` is set the server wants it: `x-api-key` for Anthropic and
`Authorization: Bearer` for OpenAI. `GET /_state` says what it has been asked (never the key,
only whether it was right), `POST /_reset` forgets it, and `GET /healthz` answers. The usage of an
OpenAI stream is sent only when the request asked for it with `stream_options.include_usage`, as
the real API does.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import os
from collections.abc import AsyncIterator, Sequence
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

REPLY_WORDS = 12
CACHE_READ = 5
CACHE_WRITE = 2
SLOW_PAUSE_S = 0.15
SLOW_ANSWER_S = 0.5


def words(value: Any) -> int:
    """The words in a string, or in the text blocks of a list of content blocks."""
    if isinstance(value, str):
        return len(value.split())
    if isinstance(value, list):
        return sum(words(block.get("text", "")) for block in value if isinstance(block, dict))
    return 0


def prompt_tokens(payload: dict[str, Any]) -> int:
    total = words(payload.get("system"))
    for message in payload.get("messages") or []:
        if isinstance(message, dict):
            total += words(message.get("content"))
    return max(total, 1)


def reply_tokens(payload: dict[str, Any]) -> int:
    asked = payload.get("max_tokens") or payload.get("max_completion_tokens") or REPLY_WORDS
    return max(1, min(int(asked), REPLY_WORDS))


def sse(event: str | None, data: Any) -> bytes:
    head = f"event: {event}\n" if event else ""
    return f"{head}data: {json.dumps(data)}\n\n".encode()


class Broken(Exception):
    """Raised inside a stream to break the connection, as a provider that fell over would."""


def create_app(api_key: str | None = None) -> FastAPI:
    app = FastAPI(title="fake-llm", docs_url=None, redoc_url=None, openapi_url=None)
    seen: list[dict[str, Any]] = []

    def presented(request: Request, kind: str) -> str:
        if kind == "anthropic":
            return request.headers.get("x-api-key", "")
        header = request.headers.get("authorization", "")
        return header[7:] if header.lower().startswith("bearer ") else ""

    def check(request: Request, kind: str, payload: dict[str, Any]) -> tuple[bool, str]:
        given = presented(request, kind)
        ok = api_key is None or hmac.compare_digest(given.encode(), api_key.encode())
        seen.append(
            {
                "path": request.url.path,
                "key_received": bool(given),
                "key_ok": ok,
                "anthropic_version": request.headers.get("anthropic-version"),
                "accept_encoding": request.headers.get("accept-encoding"),
                "header_names": sorted(request.headers),
                "other_headers": sorted(
                    name
                    for name in request.headers
                    if name.startswith(("x-keystone", "authorization-", "cookie"))
                ),
                "body": payload,
            }
        )
        return ok, given

    def refusal(kind: str, model: str, ok: bool, given: str) -> Response | None:
        if not ok or "error-echo-key" in model:
            message = (
                f"invalid x-api-key: {given}"
                if kind == "anthropic"
                else f"Incorrect API key provided: {given}."
            )
            body: dict[str, Any] = (
                {"type": "error", "error": {"type": "authentication_error", "message": message}}
                if kind == "anthropic"
                else {"error": {"message": message, "type": "invalid_request_error"}}
            )
            return JSONResponse(body, status_code=401)
        if "error-429" in model:
            body = (
                {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}
                if kind == "anthropic"
                else {"error": {"message": "slow down", "type": "rate_limit_error"}}
            )
            return JSONResponse(body, status_code=429, headers={"retry-after": "7"})
        if "error-500" in model:
            return JSONResponse({"error": {"message": "the provider fell over"}}, status_code=500)
        return None

    async def stream(events: Sequence[bytes], model: str) -> AsyncIterator[bytes]:
        for number, event in enumerate(events):
            if "cut" in model and number == 2:
                raise Broken
            if "slow" in model:
                await asyncio.sleep(SLOW_PAUSE_S)
            yield event

    @app.post("/v1/messages")
    async def messages(request: Request) -> Response:
        payload = await request.json()
        model = str(payload.get("model", ""))
        ok, given = check(request, "anthropic", payload)
        if (refused := refusal("anthropic", model, ok, given)) is not None:
            return refused
        n_in, n_out = prompt_tokens(payload), reply_tokens(payload)
        cached = "cached" in model
        usage: dict[str, int] = {"input_tokens": n_in, "output_tokens": n_out}
        if cached:
            usage |= {
                "cache_read_input_tokens": CACHE_READ,
                "cache_creation_input_tokens": CACHE_WRITE,
            }
        reply = [f"reply{number}" for number in range(1, n_out + 1)]
        message = {
            "id": "msg_fake",
            "type": "message",
            "role": "assistant",
            "model": model,
            "stop_reason": "end_turn",
            "stop_sequence": None,
        }
        if not payload.get("stream"):
            if "slow" in model:
                await asyncio.sleep(SLOW_ANSWER_S)
            return JSONResponse(
                {**message, "content": [{"type": "text", "text": " ".join(reply)}], "usage": usage}
            )
        start_usage = {**usage, "output_tokens": 1}
        events = [
            sse(
                "message_start",
                {
                    "type": "message_start",
                    "message": {**message, "content": [], "usage": start_usage},
                },
            ),
            sse(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            ),
            *[
                sse(
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": f"{word} "},
                    },
                )
                for word in reply
            ],
            sse("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ]
        if "no-usage" not in model:
            events.append(
                sse(
                    "message_delta",
                    {
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                        "usage": {"output_tokens": n_out},
                    },
                )
            )
        events.append(sse("message_stop", {"type": "message_stop"}))
        return StreamingResponse(stream(events, model), media_type="text/event-stream")

    @app.post("/v1/chat/completions")
    async def completions(request: Request) -> Response:
        payload = await request.json()
        model = str(payload.get("model", ""))
        ok, given = check(request, "openai", payload)
        if (refused := refusal("openai", model, ok, given)) is not None:
            return refused
        n_in, n_out = prompt_tokens(payload), reply_tokens(payload)
        usage: dict[str, Any] = {
            "prompt_tokens": n_in,
            "completion_tokens": n_out,
            "total_tokens": n_in + n_out,
        }
        if "cached" in model:
            usage["prompt_tokens"] = n_in + CACHE_READ
            usage["total_tokens"] += CACHE_READ
            usage["prompt_tokens_details"] = {"cached_tokens": CACHE_READ}
        reply = [f"reply{number}" for number in range(1, n_out + 1)]
        base = {"id": "chatcmpl-fake", "created": 1, "model": model}
        if not payload.get("stream"):
            if "slow" in model:
                await asyncio.sleep(SLOW_ANSWER_S)
            return JSONResponse(
                {
                    **base,
                    "object": "chat.completion",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": " ".join(reply)},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": usage,
                }
            )
        chunk = {**base, "object": "chat.completion.chunk"}
        events = [
            sse(
                None,
                {
                    **chunk,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": ""},
                            "finish_reason": None,
                        }
                    ],
                },
            ),
            *[
                sse(
                    None,
                    {
                        **chunk,
                        "choices": [
                            {"index": 0, "delta": {"content": f"{word} "}, "finish_reason": None}
                        ],
                    },
                )
                for word in reply
            ],
            sse(None, {**chunk, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
        ]
        options = payload.get("stream_options")
        if isinstance(options, dict) and options.get("include_usage") and "no-usage" not in model:
            events.append(sse(None, {**chunk, "choices": [], "usage": usage}))
        events.append(b"data: [DONE]\n\n")
        return StreamingResponse(stream(events, model), media_type="text/event-stream")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/_reset")
    async def reset() -> dict[str, str]:
        seen.clear()
        return {"status": "reset"}

    @app.get("/_state")
    async def state() -> dict[str, Any]:
        return {"requests": list(seen)}

    return app


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="fake_llm", description="A fake of two model APIs")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8199)
    args = parser.parse_args(argv)
    app = create_app(os.environ.get("FAKE_LLM_API_KEY") or None)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
