"""KS-806: reading token counts out of what the two providers send, whole or as a stream."""

import json
from typing import Any

import pytest

from keystone.metering.llm_usage import (
    MAX_BODY_BYTES,
    BodyUsage,
    StreamUsage,
    anthropic_usage,
    merge,
    openai_usage,
    read_usage,
    response_usage,
)
from keystone.metering.pricing import Usage

pytestmark = pytest.mark.phase(8)


def sse(event: str | None, data: Any) -> bytes:
    head = f"event: {event}\n" if event else ""
    return f"{head}data: {json.dumps(data)}\n\n".encode()


ANTHROPIC_STREAM = b"".join(
    [
        sse(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "model": "fake-model",
                    "usage": {
                        "input_tokens": 25,
                        "cache_read_input_tokens": 5,
                        "cache_creation_input_tokens": 2,
                        "output_tokens": 1,
                    },
                },
            },
        ),
        sse("content_block_start", {"type": "content_block_start", "index": 0}),
        sse("ping", {"type": "ping"}),
        sse("content_block_delta", {"type": "content_block_delta", "delta": {"text": "Hi"}}),
        sse("message_delta", {"type": "message_delta", "usage": {"output_tokens": 15}}),
        sse("message_stop", {"type": "message_stop"}),
    ]
)
OPENAI_STREAM = b"".join(
    [
        sse(
            None,
            {
                "id": "c1",
                "model": "fake-model",
                "choices": [{"delta": {"content": "Hi"}}],
                "usage": None,
            },
        ),
        sse(None, {"id": "c1", "choices": [{"delta": {}, "finish_reason": "stop"}]}),
        sse(
            None,
            {
                "choices": [],
                "usage": {
                    "prompt_tokens": 9,
                    "completion_tokens": 12,
                    "total_tokens": 21,
                    "prompt_tokens_details": {"cached_tokens": 4},
                },
            },
        ),
        b"data: [DONE]\n\n",
    ]
)


def test_anthropic_counts_its_four_kinds_of_token() -> None:
    usage = anthropic_usage(
        {
            "input_tokens": 25,
            "output_tokens": 15,
            "cache_read_input_tokens": 5,
            "cache_creation_input_tokens": 2,
        }
    )

    assert usage == Usage(25, 15, 5, 2)


def test_openai_counts_cached_tokens_inside_the_prompt_and_they_are_taken_out_of_it() -> None:
    usage = openai_usage(
        {"prompt_tokens": 9, "completion_tokens": 12, "prompt_tokens_details": {"cached_tokens": 4}}
    )

    assert usage == Usage(input_tokens=5, output_tokens=12, cache_read_tokens=4)
    assert usage.total_input == 9


def test_cached_tokens_cannot_exceed_the_prompt() -> None:
    usage = openai_usage({"prompt_tokens": 3, "prompt_tokens_details": {"cached_tokens": 10}})

    assert usage == Usage(input_tokens=0, cache_read_tokens=3)


@pytest.mark.parametrize("junk", [None, "12", -4, 1.5, True, [], {}])
def test_a_count_that_is_not_a_whole_number_of_tokens_is_nothing(junk: Any) -> None:
    assert anthropic_usage({"input_tokens": junk, "output_tokens": junk}) == Usage()
    assert openai_usage({"prompt_tokens": junk, "completion_tokens": junk}) == Usage()


def test_usage_that_is_not_an_object_is_not_usage() -> None:
    assert read_usage("anthropic", None) is None
    assert read_usage("openai", "12") is None
    assert read_usage("openai", []) is None


def test_a_whole_response_gives_its_usage_and_its_model() -> None:
    body = json.dumps({"model": "fake-model", "usage": {"input_tokens": 4, "output_tokens": 12}})

    assert response_usage("anthropic", body.encode()) == (Usage(4, 12), "fake-model")


@pytest.mark.parametrize("body", [b"", b"not json", b"[1, 2]", b'"text"', b'{"usage": 3}'])
def test_a_body_that_has_no_usage_gives_none(body: bytes) -> None:
    assert response_usage("openai", body)[0] is None


def test_merging_keeps_the_larger_of_each_count() -> None:
    assert merge(None, Usage(1, 2)) == Usage(1, 2)
    assert merge(Usage(25, 1, 5, 2), Usage(0, 15)) == Usage(25, 15, 5, 2)


def read_stream(provider: str, stream: bytes, size: int) -> StreamUsage:
    reader = StreamUsage(provider)  # type: ignore[arg-type]
    for start in range(0, len(stream), size):
        reader.feed(stream[start : start + size])
    reader.finish()
    return reader


@pytest.mark.parametrize("size", [1, 2, 3, 7, 16, 64, 1000, 10**6])
def test_an_anthropic_stream_gives_the_same_usage_whatever_the_chunks(size: int) -> None:
    reader = read_stream("anthropic", ANTHROPIC_STREAM, size)

    # The input from message_start, the output counted up to the end from message_delta.
    assert reader.usage == Usage(25, 15, 5, 2)
    assert reader.model == "fake-model"
    assert reader.dropped_lines == 0


@pytest.mark.parametrize("size", [1, 2, 3, 7, 16, 64, 1000, 10**6])
def test_an_openai_stream_gives_the_same_usage_whatever_the_chunks(size: int) -> None:
    reader = read_stream("openai", OPENAI_STREAM, size)

    assert reader.usage == Usage(input_tokens=5, output_tokens=12, cache_read_tokens=4)
    assert reader.model == "fake-model"
    assert reader.done is True


def test_a_stream_with_no_usage_says_nothing_was_seen() -> None:
    reader = read_stream("openai", OPENAI_STREAM.split(b'data: {"choices": []')[0], 64)

    assert reader.usage is None and reader.events >= 1


def test_an_anthropic_stream_that_broke_before_the_end_keeps_what_the_start_said() -> None:
    cut = ANTHROPIC_STREAM[: ANTHROPIC_STREAM.index(b"event: message_delta")]

    reader = read_stream("anthropic", cut, 50)

    assert reader.usage == Usage(25, 1, 5, 2)


def test_lines_that_are_not_events_are_ignored_and_bad_json_is_counted() -> None:
    stream = (
        b": a comment\n"
        b"event: ping\n"
        b"\n"
        b"data: {not json}\n"
        b"data: [1, 2]\n"
        b"data: "
        + json.dumps({"usage": {"prompt_tokens": 2, "completion_tokens": 3}}).encode()
        + b"\n"
    )

    reader = read_stream("openai", stream, 5)

    assert reader.usage == Usage(input_tokens=2, output_tokens=3)
    assert reader.dropped_lines == 1


def test_windows_line_endings_are_read_too() -> None:
    reader = read_stream("openai", OPENAI_STREAM.replace(b"\n", b"\r\n"), 11)

    assert reader.usage is not None and reader.usage.output_tokens == 12


def test_a_last_line_with_no_newline_is_read_when_the_stream_ends() -> None:
    last = b"data: " + json.dumps({"usage": {"prompt_tokens": 1, "completion_tokens": 2}}).encode()

    reader = read_stream("openai", last, 4)

    assert reader.usage == Usage(input_tokens=1, output_tokens=2)


def test_a_line_that_never_ends_is_dropped_and_does_not_grow_without_bound() -> None:
    reader = StreamUsage("openai")

    for _ in range(40):
        reader.feed(b"x" * 100_000)

    assert reader.dropped_lines >= 1
    assert len(reader._buffer) <= 1024 * 1024 + 100_000


def test_a_stream_reader_does_not_raise_on_anything() -> None:
    reader = StreamUsage("anthropic")

    for chunk in (b"\x00\xff\xfe", b"data: \xff\n", b"data:\n", b"data: null\n", b"data: 5\n"):
        reader.feed(chunk)
    reader.finish()

    assert reader.usage is None


def test_usage_is_final_when_the_provider_has_given_its_last_count() -> None:
    cut = ANTHROPIC_STREAM[: ANTHROPIC_STREAM.index(b"event: message_delta")]

    started = read_stream("anthropic", cut, 50)
    whole = read_stream("anthropic", ANTHROPIC_STREAM, 50)
    openai = read_stream("openai", OPENAI_STREAM, 50)
    openai_cut = read_stream("openai", OPENAI_STREAM.split(b'data: {"choices": []')[0], 50)

    # Anthropic's first event has a placeholder for the output, so it is a count and not the count.
    assert started.usage is not None and started.final is False
    assert whole.final is True and openai.final is True
    assert openai_cut.usage is None and openai_cut.final is False


def test_the_usage_of_a_whole_answer_is_read_when_it_ends() -> None:
    answer = json.dumps(
        {"model": "fake-model", "usage": {"input_tokens": 4, "output_tokens": 12}}
    ).encode()
    reader = BodyUsage("anthropic")

    for start in range(0, len(answer), 7):
        reader.feed(answer[start : start + 7])
    assert reader.usage is None  # nothing is read until the end
    reader.finish()

    assert reader.usage == Usage(4, 12) and reader.model == "fake-model" and reader.final is True


@pytest.mark.parametrize("answer", [b"", b"not json", b"[1]", b'{"model": "m"}', b'{"usage": 4}'])
def test_an_answer_with_no_usage_in_it_gives_none(answer: bytes) -> None:
    reader = BodyUsage("openai")

    reader.feed(answer)
    reader.finish()

    assert reader.usage is None and reader.final is False


def test_an_answer_too_long_to_keep_is_passed_on_and_not_read() -> None:
    reader = BodyUsage("anthropic")
    answer = json.dumps({"usage": {"input_tokens": 1, "output_tokens": 2}}).encode()

    reader.feed(b" " * MAX_BODY_BYTES)
    reader.feed(answer)  # one byte over the limit is enough to stop keeping it
    reader.finish()

    assert reader.too_long is True and reader.usage is None
