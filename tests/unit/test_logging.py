import io
import json
from collections.abc import Iterator

import pytest
import structlog
from pydantic import SecretStr

from keystone.logging import configure_logging, scrub_secrets


@pytest.fixture
def stream() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    configure_logging("DEBUG", stream=buffer)
    yield buffer
    structlog.reset_defaults()


def last_line(stream: io.StringIO) -> dict[str, object]:
    return json.loads(stream.getvalue().strip().splitlines()[-1])


@pytest.mark.phase(0)
def test_scrubber_redacts_known_keys(stream: io.StringIO) -> None:
    structlog.get_logger().info("calling", api_key="abc", user="alice")

    line = last_line(stream)
    assert line["api_key"] == "[redacted]"
    assert line["user"] == "alice"
    assert "abc" not in stream.getvalue()


@pytest.mark.phase(0)
@pytest.mark.parametrize(
    "key", ["secret", "client_secret", "token", "access_token", "password", "Authorization",
            "API-KEY", "api_key", "apikey"]
)  # fmt: skip
def test_scrubber_matches_key_variants(key: str) -> None:
    event = scrub_secrets(None, "info", {"event": "x", key: "value"})

    assert event[key] == "[redacted]"


@pytest.mark.phase(0)
def test_scrubber_redacts_secret_str_under_any_key(stream: io.StringIO) -> None:
    structlog.get_logger().info("config", dsn=SecretStr("postgres://u:p@h/db"))

    assert last_line(stream)["dsn"] == "[redacted]"
    assert "postgres://" not in stream.getvalue()


@pytest.mark.phase(0)
def test_scrubber_walks_nested_values(stream: io.StringIO) -> None:
    structlog.get_logger().info(
        "nested",
        headers={"authorization": "Bearer x", "accept": "json"},
        items=[{"password": "p"}, {"name": "n"}],
    )

    line = last_line(stream)
    assert line["headers"] == {"authorization": "[redacted]", "accept": "json"}
    assert line["items"] == [{"password": "[redacted]"}, {"name": "n"}]


@pytest.mark.phase(0)
def test_log_level_filters_and_lines_are_json(stream: io.StringIO) -> None:
    configure_logging("WARNING", stream=stream)
    log = structlog.get_logger()
    log.info("quiet")
    log.warning("loud")

    lines = [json.loads(line) for line in stream.getvalue().strip().splitlines()]
    assert [line["event"] for line in lines] == ["loud"]
    assert lines[0]["level"] == "warning"
    assert "timestamp" in lines[0]
