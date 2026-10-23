"""Take credentials out of what an upstream sent back (KS-392).

Keystone adds an upstream's credential to the call itself, so the agent never holds it. An upstream
that copies a request header into its answer (a debug endpoint, an error that quotes the request)
would hand the credential to the agent anyway. The dispatcher runs every result through
`scrub_result` before it leaves dispatch, so the replacement happens before an output scanner, the
audit trail or the agent can see the original.

Two kinds of value are replaced: the ones Keystone injected for this call, whatever their length,
and every secret registered with the log scrubber (the vault registers each credential it
decrypts), so one upstream's answer cannot carry another upstream's key either. Every string in
the result is checked, in any kind of content block and at any depth, and so are object keys.

This catches a value that appears as it was sent. An upstream that changes the value first
(reverses it, splits it, encodes it) is not caught, and no replacement could be: that is what the
sandbox of Phase 8 is for.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from pydantic import SecretStr

from keystone.core.types import ToolResult
from keystone.logging import REDACTED, SECRETS


def _redactor(injected: Iterable[str | SecretStr]) -> Callable[[str], str]:
    plain = {v.get_secret_value() if isinstance(v, SecretStr) else v for v in injected}
    # Longest first, so a value that contains another is replaced whole.
    values = sorted((v for v in plain if v), key=len, reverse=True)

    def redact(text: str) -> str:
        for value in values:
            text = text.replace(value, REDACTED)
        return SECRETS.redact(text)

    return redact


def _walk(node: Any, redact: Callable[[str], str]) -> Any:
    if isinstance(node, str):
        return redact(node)
    if isinstance(node, dict):
        return {(redact(k) if isinstance(k, str) else k): _walk(v, redact) for k, v in node.items()}
    if isinstance(node, list | tuple):
        return [_walk(item, redact) for item in node]
    return node


def scrub_result(result: ToolResult, injected: Iterable[str | SecretStr] = ()) -> ToolResult:
    """The result with every injected value and every registered secret replaced by `[redacted]`.
    The input is not changed. A result that holds none of them comes back equal to it."""
    redact = _redactor(injected)
    return result.model_copy(
        update={
            "content": _walk(result.content, redact),
            "structured_content": _walk(result.structured_content, redact),
        }
    )
