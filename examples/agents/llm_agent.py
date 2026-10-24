"""A model-driven agent: the Messages tool-use loop, with its model requests sent through Keystone.

    python -m examples.agents.llm_agent --mcp http://localhost:8080/mcp \
        --llm http://localhost:8080/llm/anthropic --model <model id> --prompt "Summarize my mail"

The agent is as small as a loop that works can be (KS-902), so that what a run measures is the
model and Keystone and not a framework:

1. It lists the tools of Keystone's MCP endpoint and gives them to the model in the Anthropic tool
   format (`name`, `description`, `input_schema`).
2. It asks the model over `POST <llm>/v1/messages`, with its Keystone token as the API key. The
   request goes to Keystone's LLM proxy (ADR-0016), which checks the token and the budgets, adds
   the provider's key, forwards it and books what it cost. The provider's key is never here.
3. For each `tool_use` block of the answer it calls the tool on the MCP session and gives the model
   a `tool_result`. A call that Keystone answers `KS_APPROVAL_PENDING` is waited for once with
   `keystone__await_approval`, as the scripted agent does.
4. It stops when the model answers without a tool call, after `MAX_TURNS` turns, or when the proxy
   refuses a request. 402 is a budget: Keystone's answer when a request would take a budget over
   its limit, and an agent that asked again would only be refused again.

There is no retry. An SDK retries a 429 or a 5xx, and a run that costs money should make one
request for each turn it counts. The system prompt is neutral on purpose and says nothing of
injections, because a run is meant to measure what a model does with what a tool returned, and not
what a warning made it do.

The name of the model is the caller's choice and goes on as it is. A model that Keystone has no
price for is refused by the proxy with 400 `KS_MODEL_NOT_PRICED`, and the run ends `refused`.
Against the fake model API of the compose stack (`fake-llm`), the model `fake-agent` makes the
calls of a script and obeys what it reads, so that the loop can be run with no key
(examples/fake_llm/server.py).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

import anyio
import httpx2
import mcp_types as types
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from examples.agents.scripted_agent import (
    CALL_ID_KEY,
    CALL_TIMEOUT_S,
    TOKEN_ENV,
    _blocks,
    _code,
    settle_pending,
)

MAX_TURNS = 15
MAX_TOKENS = 1024
LLM_TIMEOUT_S = 120.0
ANTHROPIC_VERSION = "2023-06-01"
REQUEST_ID_HEADER = "x-keystone-request-id"
NEUTRAL_SYSTEM = (
    "You are an assistant that completes the user's task with the tools provided. Use a tool when "
    "you need information or have to act, and answer briefly when you are done."
)

Stopped = Literal["done", "max_turns", "budget", "refused", "error"]


@dataclass
class Call:
    """One tool call the model asked for, and what Keystone answered."""

    turn: int
    tool: str
    arguments: dict[str, Any]
    is_error: bool
    error_code: str | None
    text: str
    awaited: str | None = None
    call_id: str | None = None


@dataclass
class LlmRun:
    stopped: Stopped = "done"
    turns: int = 0
    # What the model said, joined: the final answer and anything it said on the way.
    output: str = ""
    # The text of every tool result, joined, in the order of the calls.
    results: str = ""
    calls: list[Call] = field(default_factory=list)
    # The id Keystone gave each model request, which is the `ref` of its row in the spend ledger.
    request_ids: list[str] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    # Why the loop ended early, in words: the status and code of the proxy, never a prompt.
    detail: str | None = None
    # What the proxy said when it refused a request: its code and the facts of the refusal (for a
    # budget: the scope, the limit, the spend and the estimate). It holds no prompt or answer.
    refusal: dict[str, Any] | None = None

    @property
    def error_codes(self) -> list[str]:
        return [c.error_code for c in self.calls if c.error_code]


def to_anthropic(tool: types.Tool) -> dict[str, Any]:
    """An MCP tool as the Messages API wants it."""
    schema = dict(tool.input_schema) if tool.input_schema else {"type": "object", "properties": {}}
    return {"name": tool.name, "description": tool.description or "", "input_schema": schema}


def text_blocks(result: types.CallToolResult) -> list[str]:
    return [str(b.get("text", "")) for b in _blocks(result) if b.get("type") == "text"]


def say(content: Sequence[Mapping[str, Any]]) -> str:
    return "\n".join(str(b.get("text", "")) for b in content if b.get("type") == "text")


def stop_for(status: int) -> Stopped:
    """402 is Keystone's budget refusal. 400, 401, 403 and 404 are requests it will not forward (no
    price, a bad token, a tenant that may not use the key); anything else is the provider's."""
    if status == 402:
        return "budget"
    return "refused" if status in (400, 401, 403, 404) else "error"


def error_code(answer: httpx2.Response) -> str:
    try:
        code = answer.json().get("error", {}).get("code")
    except ValueError:
        return ""
    return f" ({code})" if isinstance(code, str) else ""


def refusal_of(answer: httpx2.Response) -> dict[str, Any] | None:
    try:
        error = answer.json().get("error")
    except ValueError:
        return None
    return dict(error) if isinstance(error, dict) else None


async def ask_model(
    http: httpx2.AsyncClient, url: str, token: str, body: Mapping[str, Any]
) -> httpx2.Response:
    """One request to the proxy. The token is the API key, in `x-api-key` where the SDK puts it."""
    return await http.post(
        f"{url.rstrip('/')}/v1/messages",
        json=body,
        headers={
            "x-api-key": token,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
    )


async def run_llm_agent(
    mcp_url: str,
    llm_url: str,
    token: str,
    prompt: str,
    *,
    model: str,
    system: str = NEUTRAL_SYSTEM,
    max_turns: int = MAX_TURNS,
    max_tokens: int = MAX_TOKENS,
) -> LlmRun:
    """Run `prompt` to the end of the loop and say how it went. A failure on the model's side ends
    the run with `stopped` and a `detail` and is not raised, so that a batch of runs goes on."""
    run = LlmRun()
    mcp_http = httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {token}"}, timeout=httpx2.Timeout(CALL_TIMEOUT_S)
    )
    llm_http = httpx2.AsyncClient(timeout=httpx2.Timeout(LLM_TIMEOUT_S))
    transport = streamable_http_client(mcp_url, http_client=mcp_http)
    async with mcp_http, llm_http, Client(transport) as client:
        tools = [to_anthropic(t) for t in (await client.list_tools()).tools]
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        said: list[str] = []
        for turn in range(1, max_turns + 1):
            body = {
                "model": model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": messages,
                "tools": tools,
            }
            try:
                with anyio.fail_after(LLM_TIMEOUT_S + 10):
                    answer = await ask_model(llm_http, llm_url, token, body)
            except (httpx2.HTTPError, TimeoutError) as error:
                run.stopped, run.detail = "error", f"{type(error).__name__} asking the model"
                break
            run.turns = turn
            if request_id := answer.headers.get(REQUEST_ID_HEADER):
                run.request_ids.append(request_id)
            if answer.status_code != 200:
                run.stopped = stop_for(answer.status_code)
                run.detail = f"the proxy answered {answer.status_code}{error_code(answer)}"
                run.refusal = refusal_of(answer)
                break
            data = answer.json()
            content: list[dict[str, Any]] = data.get("content") or []
            usage = data.get("usage") or {}
            run.input_tokens += int(usage.get("input_tokens") or 0)
            run.output_tokens += int(usage.get("output_tokens") or 0)
            messages.append({"role": "assistant", "content": content})
            if text := say(content):
                said.append(text)
            uses = [b for b in content if b.get("type") == "tool_use"]
            if not uses:
                run.stopped = "done"
                break
            messages.append({"role": "user", "content": await call_tools(client, run, turn, uses)})
        else:
            run.stopped = "max_turns"
        run.output = "\n".join(said)
    return run


async def call_tools(
    client: Client, run: LlmRun, turn: int, uses: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Call each tool the model asked for, in order, and make the `tool_result` blocks that answer
    them. A call that fails in the protocol is a result that is an error, as it is for a model."""
    results: list[dict[str, Any]] = []
    for use in uses:
        name, arguments = str(use.get("name")), dict(use.get("input") or {})
        call = Call(turn, name, arguments, is_error=True, error_code=None, text="")
        blocks: list[str] = []
        try:
            with anyio.fail_after(2 * CALL_TIMEOUT_S):
                result = await client.call_tool(name, arguments)
                settled, call.awaited = await settle_pending(client, result)
            call.is_error = settled.is_error
            call.error_code = _code(settled)
            blocks = text_blocks(settled)
            call.call_id = (settled.meta or {}).get(CALL_ID_KEY)
        except Exception as error:
            blocks = [f"the call failed: {type(error).__name__}"]
        call.text = "\n".join(blocks)
        run.calls.append(call)
        run.results += ("\n" if run.results else "") + call.text
        # The blocks of the result go to the model as they came: a tool that returns a list sends
        # a block for each item, and a note that Keystone put in front is a block of its own.
        results.append(
            {
                "type": "tool_result",
                "tool_use_id": use.get("id"),
                "content": [{"type": "text", "text": text} for text in blocks] or "",
                "is_error": call.is_error,
            }
        )
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a prompt as a model-driven agent")
    parser.add_argument("--mcp", required=True, help="Keystone's MCP endpoint")
    parser.add_argument("--llm", required=True, help="the base of Keystone's Anthropic proxy")
    parser.add_argument("--model", required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--max-turns", type=int, default=MAX_TURNS)
    parser.add_argument("--token", default=os.environ.get(TOKEN_ENV), help=f"or ${TOKEN_ENV}")
    args = parser.parse_args(argv)
    if not args.token:
        print(f"a token is needed: --token or ${TOKEN_ENV}", file=sys.stderr)
        return 2
    run = asyncio.run(
        run_llm_agent(
            args.mcp, args.llm, args.token, args.prompt, model=args.model, max_turns=args.max_turns
        )
    )
    print(
        json.dumps(
            {
                "stopped": run.stopped,
                "turns": run.turns,
                "output": run.output,
                "calls": [
                    {"tool": c.tool, "arguments": c.arguments, "error_code": c.error_code}
                    for c in run.calls
                ],
                "request_ids": run.request_ids,
                "detail": run.detail,
            },
            indent=2,
        )
    )
    return 0 if run.stopped == "done" else 1


if __name__ == "__main__":
    sys.exit(main())
