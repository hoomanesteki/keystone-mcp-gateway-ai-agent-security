import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any, TextIO

import structlog
from pydantic import SecretBytes, SecretStr

REDACTED = "[redacted]"
SENSITIVE_KEY = re.compile(r"(?i)(secret|token|password|api[_-]?key|authorization)")


def _scrub(key: str | None, value: Any) -> Any:
    if isinstance(value, SecretStr | SecretBytes):
        return REDACTED
    if key is not None and SENSITIVE_KEY.search(key):
        return REDACTED
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
