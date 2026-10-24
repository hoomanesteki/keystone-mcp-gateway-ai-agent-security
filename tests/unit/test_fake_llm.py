"""The fake model API (KS-806): the numbers the proxy tests work out their costs from."""

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from examples.fake_llm.server import Broken, create_app

pytestmark = pytest.mark.phase(8)

KEY = "fake-key-for-the-unit-tests"
ANTHROPIC = "/v1/messages"
OPENAI = "/v1/chat/completions"
# Four words in the prompt.
MESSAGES = [{"role": "user", "content": "hello there general kenobi"}]


def client(key: str | None = KEY) -> TestClient:
    return TestClient(create_app(key))


def anthropic(model: str = "fake-model", **extra: Any) -> dict[str, Any]:
    return {"model": model, "max_tokens": 16, "messages": MESSAGES, **extra}


def events(text: str) -> list[dict[str, Any]]:
    return [
        json.loads(line[5:])
        for line in text.splitlines()
        if line.startswith("data:") and line[5:].strip() != "[DONE]"
    ]


def test_an_anthropic_answer_reports_four_tokens_in_and_twelve_out() -> None:
    answer = client().post(ANTHROPIC, json=anthropic(), headers={"x-api-key": KEY})

    assert answer.status_code == 200
    body = answer.json()
    assert body["usage"] == {"input_tokens": 4, "output_tokens": 12}
    assert body["model"] == "fake-model"
    assert body["content"][0]["text"].split()[:2] == ["reply1", "reply2"]


def test_an_anthropic_stream_gives_the_input_first_and_the_output_at_the_end() -> None:
    answer = client().post(ANTHROPIC, json=anthropic(stream=True), headers={"x-api-key": KEY})

    sent = events(answer.text)
    assert answer.headers["content-type"].startswith("text/event-stream")
    assert sent[0]["type"] == "message_start"
    assert sent[0]["message"]["usage"] == {"input_tokens": 4, "output_tokens": 1}
    assert sent[-2]["type"] == "message_delta" and sent[-2]["usage"] == {"output_tokens": 12}
    assert sent[-1]["type"] == "message_stop"
    assert sum(e["type"] == "content_block_delta" for e in sent) == 12


def test_a_cached_model_adds_cache_tokens_to_both_shapes() -> None:
    http = client()

    one = http.post(
        ANTHROPIC, json=anthropic("fake-model-cached"), headers={"x-api-key": KEY}
    ).json()
    two = http.post(
        OPENAI,
        json=anthropic("fake-model-cached"),
        headers={"authorization": f"Bearer {KEY}"},
    ).json()

    assert one["usage"] == {
        "input_tokens": 4,
        "output_tokens": 12,
        "cache_read_input_tokens": 5,
        "cache_creation_input_tokens": 2,
    }
    # OpenAI counts the cached tokens inside prompt_tokens and says how many they were.
    assert two["usage"]["prompt_tokens"] == 9
    assert two["usage"]["prompt_tokens_details"] == {"cached_tokens": 5}


def test_an_openai_answer_reports_prompt_and_completion_tokens() -> None:
    answer = client().post(OPENAI, json=anthropic(), headers={"authorization": f"Bearer {KEY}"})

    assert answer.json()["usage"] == {
        "prompt_tokens": 4,
        "completion_tokens": 12,
        "total_tokens": 16,
    }


def test_an_openai_stream_reports_usage_only_when_it_was_asked_to() -> None:
    http = client()
    headers = {"authorization": f"Bearer {KEY}"}

    plain = http.post(OPENAI, json=anthropic(stream=True), headers=headers).text
    asked = http.post(
        OPENAI,
        json=anthropic(stream=True, stream_options={"include_usage": True}),
        headers=headers,
    ).text

    assert not any("usage" in e for e in events(plain))
    last = events(asked)[-1]
    assert last["choices"] == [] and last["usage"]["completion_tokens"] == 12
    assert asked.rstrip().endswith("data: [DONE]")


def test_a_model_that_says_nothing_of_its_usage_leaves_it_out() -> None:
    http = client()

    one = http.post(
        ANTHROPIC, json=anthropic("fake-no-usage", stream=True), headers={"x-api-key": KEY}
    ).text
    two = http.post(
        OPENAI,
        json=anthropic("fake-no-usage", stream=True, stream_options={"include_usage": True}),
        headers={"authorization": f"Bearer {KEY}"},
    ).text

    assert [e["type"] for e in events(one) if e["type"] == "message_delta"] == []
    assert not any("usage" in e for e in events(two))


def test_a_stream_that_is_cut_breaks_the_connection() -> None:
    with pytest.raises(Broken):
        client().post(
            ANTHROPIC, json=anthropic("fake-cut", stream=True), headers={"x-api-key": KEY}
        )


def test_the_failures_a_test_can_ask_for() -> None:
    http = client()
    headers = {"x-api-key": KEY}

    limited = http.post(ANTHROPIC, json=anthropic("fake-error-429"), headers=headers)
    broken = http.post(ANTHROPIC, json=anthropic("fake-error-500"), headers=headers)

    assert limited.status_code == 429 and limited.headers["retry-after"] == "7"
    assert broken.status_code == 500


def test_a_wrong_key_is_refused_and_the_refusal_repeats_it() -> None:
    http = client()

    refused = http.post(ANTHROPIC, json=anthropic(), headers={"x-api-key": "not-the-key"})
    echoing = http.post(
        ANTHROPIC, json=anthropic("fake-error-echo-key"), headers={"x-api-key": KEY}
    )

    assert refused.status_code == 401
    assert "not-the-key" in refused.text
    # The model that echoes does so for the right key as well, which is the proxy's problem to hide.
    assert echoing.status_code == 401 and KEY in echoing.text


def test_what_it_was_asked_is_kept_without_the_key() -> None:
    http = client()
    http.post(ANTHROPIC, json=anthropic(), headers={"x-api-key": KEY, "anthropic-version": "v"})
    http.post(OPENAI, json=anthropic(), headers={"authorization": "Bearer wrong"})

    seen = http.get("/_state").json()["requests"]

    assert [(r["path"], r["key_received"], r["key_ok"]) for r in seen] == [
        (ANTHROPIC, True, True),
        (OPENAI, True, False),
    ]
    assert seen[0]["anthropic_version"] == "v"
    assert KEY not in json.dumps(seen) and "wrong" not in json.dumps(seen)
    assert http.post("/_reset").status_code == 200
    assert http.get("/_state").json() == {"requests": []}


def test_without_a_key_configured_it_takes_any_request() -> None:
    answer = client(None).post(ANTHROPIC, json=anthropic())

    assert answer.status_code == 200
