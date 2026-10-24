"""Reading token counts out of what a provider sent (KS-806).

Two APIs, two shapes. The count is the provider's own and it is the only number the cost is made
from: the proxy never counts tokens itself, except for the estimate that a budget is checked against
before the request is made.

- Anthropic: `usage.input_tokens`, `usage.output_tokens`, `usage.cache_read_input_tokens` and
  `usage.cache_creation_input_tokens`. In a stream the input arrives in `message_start` and the
  output, counted up to the end, in `message_delta`.
- OpenAI chat completions: `usage.prompt_tokens` (cached tokens included, with their number in
  `prompt_tokens_details.cached_tokens`) and `usage.completion_tokens`. A stream carries the usage
  in a last chunk with no choices, and only when the request asked for it with
  `stream_options.include_usage`.

A stream is read as it passes, by `StreamUsage`, which never raises: the bytes go to the client
whether or not they make sense here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Literal, Protocol

from keystone.metering.pricing import Usage

Provider = Literal["anthropic", "openai"]

# The most of a whole answer that is kept to read its usage. A longer answer is still passed on,
# and its usage is not read.
MAX_BODY_BYTES = 16 * 1024 * 1024
# A line of a stream longer than this is not an event of either API, and is dropped so that a
# provider that never sends a newline cannot make the proxy hold the stream in memory.
MAX_LINE_BYTES = 1024 * 1024


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def anthropic_usage(raw: Mapping[str, Any]) -> Usage:
    return Usage(
        input_tokens=_count(raw.get("input_tokens")),
        output_tokens=_count(raw.get("output_tokens")),
        cache_read_tokens=_count(raw.get("cache_read_input_tokens")),
        cache_write_tokens=_count(raw.get("cache_creation_input_tokens")),
    )


def openai_usage(raw: Mapping[str, Any]) -> Usage:
    prompt = _count(raw.get("prompt_tokens"))
    details = raw.get("prompt_tokens_details")
    cached = _count(details.get("cached_tokens")) if isinstance(details, Mapping) else 0
    cached = min(cached, prompt)
    return Usage(
        input_tokens=prompt - cached,
        output_tokens=_count(raw.get("completion_tokens")),
        cache_read_tokens=cached,
    )


def read_usage(provider: Provider, raw: Any) -> Usage | None:
    """The usage in a `usage` object, or None when it is not one."""
    if not isinstance(raw, Mapping):
        return None
    return anthropic_usage(raw) if provider == "anthropic" else openai_usage(raw)


def response_usage(provider: Provider, body: bytes) -> tuple[Usage | None, str | None]:
    """The usage and the model of a whole response, or (None, None) for a body that is not one."""
    try:
        parsed = json.loads(body)
    except ValueError:
        return None, None
    if not isinstance(parsed, Mapping):
        return None, None
    model = parsed.get("model")
    return read_usage(provider, parsed.get("usage")), model if isinstance(model, str) else None


def merge(left: Usage | None, right: Usage) -> Usage:
    """The larger of each count. The counts of a stream only grow, so the last one is the largest,
    and a count that a later event leaves out is not lost."""
    if left is None:
        return right
    return Usage(
        input_tokens=max(left.input_tokens, right.input_tokens),
        output_tokens=max(left.output_tokens, right.output_tokens),
        cache_read_tokens=max(left.cache_read_tokens, right.cache_read_tokens),
        cache_write_tokens=max(left.cache_write_tokens, right.cache_write_tokens),
    )


class UsageReader(Protocol):
    """What the proxy feeds each chunk of an answer to, and reads the usage from at the end."""

    usage: Usage | None
    model: str | None
    # True once the provider has given its final count. Anthropic's first event carries the input
    # tokens and a placeholder for the output, so a stream cut before its last event has a usage
    # that is not final.
    final: bool

    def feed(self, chunk: bytes) -> None: ...

    def finish(self) -> None: ...


class BodyUsage:
    """Reads the usage of an answer that is not a stream: one JSON object, kept while it passes."""

    def __init__(self, provider: Provider) -> None:
        self._provider = provider
        self._body = bytearray()
        self.usage: Usage | None = None
        self.model: str | None = None
        self.final = False
        self.too_long = False

    def feed(self, chunk: bytes) -> None:
        if self.too_long:
            return
        if len(self._body) + len(chunk) > MAX_BODY_BYTES:
            self.too_long = True
            self._body.clear()
            return
        self._body += chunk

    def finish(self) -> None:
        if not self.too_long:
            self.usage, self.model = response_usage(self._provider, bytes(self._body))
            self.final = self.usage is not None
        self._body.clear()


class StreamUsage:
    """Reads the usage of a server-sent-event stream from the chunks that pass through. Chunks may
    end anywhere, in the middle of a line or of a multi-byte character."""

    def __init__(self, provider: Provider) -> None:
        self._provider = provider
        self._buffer = bytearray()
        self.usage: Usage | None = None
        self.model: str | None = None
        self.final = False
        self.events = 0
        self.dropped_lines = 0
        self.done = False

    def feed(self, chunk: bytes) -> None:
        self._buffer += chunk
        while (newline := self._buffer.find(b"\n")) >= 0:
            line = bytes(self._buffer[:newline]).rstrip(b"\r")
            del self._buffer[: newline + 1]
            self._line(line)
        if len(self._buffer) > MAX_LINE_BYTES:
            self._buffer.clear()
            self.dropped_lines += 1

    def finish(self) -> None:
        """The stream has ended: a last line that had no newline is still a line."""
        if self._buffer:
            line = bytes(self._buffer).rstrip(b"\r")
            self._buffer.clear()
            self._line(line)

    def _line(self, line: bytes) -> None:
        if not line.startswith(b"data:"):
            return  # `event:` names, comments, blank lines
        data = line[5:].strip()
        if data == b"[DONE]":
            self.done = True
            return
        try:
            event = json.loads(data)
        except ValueError:
            self.dropped_lines += 1
            return
        if not isinstance(event, Mapping):
            return
        self.events += 1
        if self._provider == "anthropic":
            kind = event.get("type")
            carrier = event.get("message") if kind == "message_start" else event
            if kind in ("message_start", "message_delta") and isinstance(carrier, Mapping):
                self._take(
                    carrier.get("usage"), carrier.get("model"), final=kind == "message_delta"
                )
        else:
            self._take(event.get("usage"), event.get("model"), final=True)

    def _take(self, raw: Any, model: Any, *, final: bool) -> None:
        if isinstance(model, str) and self.model is None:
            self.model = model
        found = read_usage(self._provider, raw)
        if found is not None:
            self.usage = merge(self.usage, found)
            self.final = self.final or final
