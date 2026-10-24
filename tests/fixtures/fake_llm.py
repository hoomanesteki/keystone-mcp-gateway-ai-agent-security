"""The fake model API (examples/fake_llm) in a background thread, and the settings that point the
LLM proxy at it (KS-806).

The fake wants a key, so a proxy that forwards a request without the provider's key is refused by it
and the test sees the 401. The key is a canary: a test that searches a response, a log or a span for
it knows exactly what it is looking for. The prices are fake too, and are not any provider's.
"""

import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

from examples.fake_llm.server import create_app
from keystone.settings import LlmProviderSettings, LlmProxySettings
from tests.fixtures.servers import ServerThread

# Fake prices in dollars for each million tokens. With them a request of 4 words in and 12 words
# out costs (4 * 3 + 12 * 15) / 1,000,000 = $0.000192, and the numbers below are worked out from
# the same table.
FAKE_PRICES = """\
models:
  fake-model:
    input_per_mtok: 3.00
    output_per_mtok: 15.00
  fake-model-cached:
    input_per_mtok: 3.00
    output_per_mtok: 15.00
    cache_read_per_mtok: 0.30
    cache_write_per_mtok: 3.75
  fake-*:
    input_per_mtok: 3.00
    output_per_mtok: 15.00
"""
# The environment variables that hold the provider keys in the test apps.
ANTHROPIC_VARIABLE = "TEST_ANTHROPIC_KEY"
OPENAI_VARIABLE = "TEST_OPENAI_KEY"
# Four words of prompt and a reply of twelve (max_tokens 16 is cut to twelve by the fake).
PROMPT = "hello there general kenobi"
COST_OF_ONE_CALL = "0.000192"


@dataclass
class FakeLlm:
    thread: ServerThread
    key: str

    @property
    def url(self) -> str:
        return self.thread.url

    def environ(self) -> dict[str, str]:
        """The provider keys as the environment the app under test reads them from."""
        return {ANTHROPIC_VARIABLE: self.key, OPENAI_VARIABLE: self.key}

    def requests(self) -> list[dict[str, Any]]:
        """What the fake has been asked since it was reset: path, whether a key came and was
        right, the headers that matter, and the body."""
        response = httpx.get(f"{self.url}/_state", timeout=10)
        response.raise_for_status()
        found: list[dict[str, Any]] = response.json()["requests"]
        return found

    def post(self, path: str, payload: dict[str, Any]) -> httpx.Response:
        """A request made straight to the fake with its key, to compare with one that went through
        Keystone."""
        headers = (
            {"x-api-key": self.key}
            if path == "/v1/messages"
            else {"authorization": f"Bearer {self.key}"}
        )
        return httpx.post(f"{self.url}{path}", json=payload, headers=headers, timeout=30)

    def reset(self) -> None:
        httpx.post(f"{self.url}/_reset", timeout=10).raise_for_status()

    def settings(self, prices: Path, **overrides: Any) -> LlmProxySettings:
        """The proxy's settings for a test app: both providers are this fake."""
        options: dict[str, Any] = {
            "enabled": True,
            "tenant": "acme",
            "pricing_file": prices,
            "anthropic": LlmProviderSettings(base_url=self.url, api_key_env=ANTHROPIC_VARIABLE),
            "openai": LlmProviderSettings(base_url=self.url, api_key_env=OPENAI_VARIABLE),
        }
        options.update(overrides)
        return LlmProxySettings(**options)


@pytest.fixture
def fake_llm() -> Iterator[FakeLlm]:
    key = f"fake-provider-key-{secrets.token_hex(12)}"
    thread = ServerThread(create_app(key)).start()
    try:
        yield FakeLlm(thread, key)
    finally:
        thread.stop()


@pytest.fixture
def fake_prices(tmp_path: Path) -> Path:
    path = tmp_path / "pricing.yaml"
    path.write_text(FAKE_PRICES)
    return path
