import io
import json
from collections.abc import Iterator

import pytest
import structlog
from pydantic import SecretStr

from keystone.logging import SECRETS, configure_logging, register_secret, scrub_secrets


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


@pytest.fixture
def registry_cleared() -> Iterator[None]:
    SECRETS.clear()
    yield
    SECRETS.clear()


@pytest.mark.phase(3)
@pytest.mark.usefixtures("registry_cleared")
def test_a_registered_secret_is_replaced_wherever_it_appears(stream: io.StringIO) -> None:
    register_secret("canary-0123456789")

    structlog.get_logger().info(
        "calling canary-0123456789 now",
        note="header was canary-0123456789.",
        nested={"deep": ["x canary-0123456789 y"]},
    )

    line = last_line(stream)
    assert line["event"] == "calling [redacted] now"
    assert line["note"] == "header was [redacted]."
    assert line["nested"] == {"deep": ["x [redacted] y"]}
    assert "canary-0123456789" not in stream.getvalue()


@pytest.mark.phase(3)
@pytest.mark.usefixtures("registry_cleared")
def test_a_secret_inside_an_exception_message_is_replaced(stream: io.StringIO) -> None:
    register_secret("canary-0123456789")

    try:
        raise RuntimeError("the upstream said: bad key canary-0123456789")
    except RuntimeError:
        structlog.get_logger().exception("dispatch_failed")

    assert "canary-0123456789" not in stream.getvalue()
    assert "[redacted]" in str(last_line(stream)["exception"])


@pytest.mark.phase(3)
@pytest.mark.usefixtures("registry_cleared")
def test_a_secret_shorter_than_eight_characters_is_left_alone(stream: io.StringIO) -> None:
    assert register_secret("short") is False
    assert register_secret("exactly8") is True

    structlog.get_logger().info("the word short stays; exactly8 goes")

    assert last_line(stream)["event"] == "the word short stays; [redacted] goes"


@pytest.mark.phase(3)
@pytest.mark.usefixtures("registry_cleared")
def test_a_pydantic_secret_can_be_registered_and_the_longer_secret_wins() -> None:
    register_secret(SecretStr("prefix-secret"))
    register_secret("prefix-secret-and-more")

    assert (
        SECRETS.redact("a prefix-secret-and-more b prefix-secret c")
        == "a [redacted] b [redacted] c"
    )


@pytest.mark.phase(3)
def test_without_registered_secrets_text_is_unchanged(registry_cleared: None) -> None:
    assert SECRETS.redact("nothing to hide") == "nothing to hide"
