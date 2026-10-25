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
| `agent` | on `/v1/messages` with `tools`, a deterministic agent that calls tools (below) |

A model whose name contains `agent`, asked with `tools`, answers like the worst-case agent of
KS-708 with a script, so that the loop of `examples/agents/llm_agent.py`, the metering of the proxy
and a budget that stops it can be exercised with no key. Each answer is one `tool_use` or the
word "Done.":

1. If a tool result of the conversation holds a `<!--ks-do:...-->` marker (examples/injections.py)
   for a tool it was given and has not called with those arguments, it calls that tool: it obeys
   what it reads, before anything else.
2. Otherwise it makes the next call of its script that it has not made. The script is a
   `<!--ks-script:[{"tool": "mail__list_emails", "args": {}}, ...]-->` comment in the first user
   message. With none, the script is one call of `keystone__whoami`, if it is given that tool.
3. Otherwise it says "Done." and the stop reason is `end_turn`.

It does not stream. The tokens in are the words of the system prompt, of every message, of the
tool results and of the inputs of its earlier calls, so a conversation costs more with each turn.

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
import re
from collections.abc import AsyncIterator, Sequence
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from examples.injections import find_markers, readable

REPLY_WORDS = 12
CACHE_READ = 5
CACHE_WRITE = 2
SLOW_PAUSE_S = 0.15
SLOW_ANSWER_S = 0.5


def words(value: Any) -> int:
    """The words in a string, or in the content blocks of a list: the text of a text block, what a
    tool returned, and the input of a tool call."""
    if isinstance(value, str):
        return len(value.split())
    if isinstance(value, list):
        return sum(block_words(block) for block in value if isinstance(block, dict))
    return 0


def block_words(block: dict[str, Any]) -> int:
    if block.get("type") == "tool_result":
        return words(block.get("content"))
    if block.get("type") == "tool_use":
        return words(json.dumps(block.get("input") or {}))
    return words(block.get("text", ""))


def prompt_tokens(payload: dict[str, Any]) -> int:
    total = words(payload.get("system"))
    for message in payload.get("messages") or []:
        if isinstance(message, dict):
            total += words(message.get("content"))
    return max(total, 1)


def reply_tokens(payload: dict[str, Any]) -> int:
    asked = payload.get("max_tokens") or payload.get("max_completion_tokens") or REPLY_WORDS
    return max(1, min(int(asked), REPLY_WORDS))


# -- the agent mode: a model that makes the calls of a script, and obeys what it reads

SCRIPT_COMMENT = re.compile(r"<!--ks-script:(\[.*?\])-->", re.DOTALL)
WHOAMI = "keystone__whoami"
Call = tuple[str, dict[str, Any]]


def text_of(content: Any) -> str:
    """The text of the content of a message: a string, or the text blocks of a list."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(block.get("text", "")) for block in content if isinstance(block, dict))
    return ""


def calls_made(messages: Sequence[dict[str, Any]]) -> list[Call]:
    """The tool calls the conversation holds already: name and input of each `tool_use` block."""
    found: list[Call] = []
    for message in messages:
        content = message.get("content")
        if message.get("role") == "assistant" and isinstance(content, list):
            found += [
                (str(block.get("name")), dict(block.get("input") or {}))
                for block in content
                if isinstance(block, dict) and block.get("type") == "tool_use"
            ]
    return found


def read_results(messages: Sequence[dict[str, Any]]) -> str:
    """Everything the tools returned in the conversation, as a reader of it would see it. The
    content of a result is a string or a list of text blocks, and each block is read on its own,
    because a tool that returns an object sends it as JSON and a block of JSON is read as the
    strings in it."""
    texts: list[str] = []
    for message in messages:
        content = message.get("content")
        if message.get("role") == "user" and isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    inner = block.get("content")
                    parts = inner if isinstance(inner, list) else [{"text": inner}]
                    texts += [
                        readable(str(part.get("text") or ""))
                        for part in parts
                        if isinstance(part, dict)
                    ]
    return "\n".join(texts)


def script_of(messages: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The steps in the `ks-script` comment of the first user message, or none."""
    first = next((m for m in messages if m.get("role") == "user"), None)
    found = SCRIPT_COMMENT.search(text_of(first.get("content")) if first else "")
    if found is None:
        return []
    try:
        steps = json.loads(found.group(1))
    except ValueError:
        return []
    return [s for s in steps if isinstance(s, dict) and isinstance(s.get("tool"), str)]


def next_call(payload: dict[str, Any]) -> Call | None:
    """The call the agent makes next, or None when it is done (see the top of this file)."""
    offered = {t.get("name") for t in payload.get("tools") or [] if isinstance(t, dict)}
    messages = [m for m in payload.get("messages") or [] if isinstance(m, dict)]
    made = calls_made(messages)
    for wanted in find_markers(read_results(messages)):
        call = (wanted.tool, dict(wanted.args))
        if wanted.tool in offered and call not in made:
            return call
    steps = script_of(messages) or ([{"tool": WHOAMI}] if WHOAMI in offered else [])
    for step in steps:
        args = step.get("args")
        call = (step["tool"], dict(args) if isinstance(args, dict) else {})
        if step["tool"] in offered and call not in made:
            return call
    return None


def agent_message(payload: dict[str, Any], model: str) -> dict[str, Any]:
    """The answer of the agent mode, in the shape of Anthropic's Messages API."""
    call = next_call(payload)
    turn = sum(1 for m in payload.get("messages") or [] if m.get("role") == "assistant") + 1
    content: list[dict[str, Any]] = (
        [{"type": "text", "text": "Done."}]
        if call is None
        else [{"type": "tool_use", "id": f"toolu_fake_{turn}", "name": call[0], "input": call[1]}]
    )
    return {
        "id": f"msg_fake_{turn}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": "end_turn" if call is None else "tool_use",
        "stop_sequence": None,
        "usage": {"input_tokens": prompt_tokens(payload), "output_tokens": reply_tokens(payload)},
    }


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
        if "agent" in model and payload.get("tools") is not None:
            if payload.get("stream"):
                return JSONResponse(
                    {
                        "type": "error",
                        "error": {
                            "type": "invalid_request_error",
                            "message": "the agent model does not stream",
                        },
                    },
                    status_code=400,
                )
            return JSONResponse(agent_message(payload, model))
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
