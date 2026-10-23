import logging
import re
import sys
import threading
from collections.abc import Mapping, MutableMapping
from typing import Any, TextIO

import structlog
from pydantic import SecretBytes, SecretStr

REDACTED = "[redacted]"
SENSITIVE_KEY = re.compile(r"(?i)(secret|token|password|api[_-]?key|authorization)")
# A shorter secret would match inside ordinary words and mangle every line.
MIN_SECRET_LENGTH = 8


class SecretRegistry:
    """The secret values this process has held, so that none of them is ever written to a log.

    The vault registers a credential each time it decrypts one. From then on the log scrubber
    replaces that text wherever it appears in a log line, in a field of any name and inside an
    exception message, which no key-name rule can see.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._secrets: set[str] = set()
        self._pattern: re.Pattern[str] | None = None

    def register(self, value: str | SecretStr) -> bool:
        """Remember a secret. Returns False for one too short to match safely."""
        text = value.get_secret_value() if isinstance(value, SecretStr) else value
        if len(text) < MIN_SECRET_LENGTH:
            return False
        with self._lock:
            if text not in self._secrets:
                self._secrets.add(text)
                self._pattern = None
        return True

    def redact(self, text: str) -> str:
        with self._lock:
            if not self._secrets:
                return text
            if self._pattern is None:
                longest_first = sorted(self._secrets, key=len, reverse=True)
                self._pattern = re.compile("|".join(re.escape(s) for s in longest_first))
            pattern = self._pattern
        return pattern.sub(REDACTED, text)

    def clear(self) -> None:
        with self._lock:
            self._secrets.clear()
            self._pattern = None


SECRETS = SecretRegistry()


def register_secret(value: str | SecretStr) -> bool:
    return SECRETS.register(value)


def _scrub(key: str | None, value: Any) -> Any:
    if isinstance(value, SecretStr | SecretBytes):
        return REDACTED
    if key is not None and SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, str):
        return SECRETS.redact(value)
    if isinstance(value, Mapping):
        return {k: _scrub(str(k), v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_scrub(None, item) for item in value]
    return value


def scrub_secrets(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Mask values under secret-looking keys, and any pydantic secret, before rendering."""
    return {k: _scrub(k, v) for k, v in event_dict.items()}


def configure_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            # Last before rendering, so nothing added by an earlier processor escapes it.
            scrub_secrets,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        logger_factory=structlog.PrintLoggerFactory(file=stream or sys.stdout),
        cache_logger_on_first_use=False,
    )
