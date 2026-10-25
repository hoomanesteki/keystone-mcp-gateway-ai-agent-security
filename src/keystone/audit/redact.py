"""What the audit log keeps of a call's arguments (KS-502, ADR-0009).

The log must be safe to read and still work as evidence. So the arguments are stored masked, and
next to them a digest of the original that lets anyone who holds the original prove what was sent.

- A key that looks like a secret (the log scrubber's rule) or that the operator lists has its value
  replaced by "[redacted]", whatever the value is.
- A string has these patterns masked: payment card numbers, US social security numbers, bearer
  tokens, AWS access key ids and private key blocks.
- A string over 2,048 characters is cut to its first 256 characters and the sha256 of the whole.
- The result is capped in size, so a call cannot make a row as large as its arguments.

Masking runs on the whole string before it is cut, so a card number across the cut is masked, not
half kept.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_left
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from keystone.audit.normalize import stable_json
from keystone.core.canonical import canonical_json, sha256_hex
from keystone.logging import REDACTED, SENSITIVE_KEY

# What every way of hiding a value leaves in its place: "[redacted]" for a secret key, and
# "[redacted:card]", "Bearer [redacted]" and the like for a pattern inside a string.
MASK_MARK = "[redacted"
# What a string over the limit ends with: "...[sha256:<64 hex digits>]".
CUT_STRING = re.compile(r"\.\.\.\[sha256:[0-9a-f]{64}\]\Z")
MAX_STRING = 2048
KEPT_OF_LONG_STRING = 256
MAX_DEPTH = 32
MAX_KEY = 256
# What one row may hold of the arguments, as canonical JSON. A call's arguments can be 1 MiB.
MAX_REDACTED_BYTES = 16 * 1024
TRUNCATED = "[truncated]"

# A run of digits with single spaces or dashes between them, not part of a longer run of digits.
# A card number is a stretch of whole groups inside such a run, 13 to 19 digits long, that passes
# Luhn. Whole groups, so that a number inside a longer number is not one; a stretch and not the
# run, so that an expiry or a code written after the number does not hide it (a pattern that took
# the whole run failed Luhn on the longer text and kept the number as it was).
DIGIT_RUN = re.compile(r"(?<!\d)\d(?:[ -]?\d)+(?!\d)")
DIGIT_GROUP = re.compile(r"\d+")
MIN_CARD_DIGITS, MAX_CARD_DIGITS = 13, 19
CARD_MASK = "[redacted:card]"
SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
AWS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)


@dataclass(frozen=True)
class RedactionConfig:
    """Keys to mask besides the ones that look like secrets. Compared whole and without regard to
    case: "SSN" masks the value of a key called "ssn", not of "ssn_checked"."""

    keys: frozenset[str] = frozenset()

    @classmethod
    def of(cls, keys: Iterable[str]) -> RedactionConfig:
        return cls(frozenset(key.casefold() for key in keys))


def _fold(digit: int) -> int:
    """A digit doubled, with the digits of the result added, as Luhn weighs every second one."""
    doubled = digit * 2
    return doubled - 9 if doubled > 9 else doubled


def luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = int(char)
        total += _fold(number) if index % 2 == 1 else number
    return total % 10 == 0


def _luhn_sums(digits: str) -> tuple[list[int], list[int]]:
    """Prefix sums that give the Luhn total of any stretch of `digits` in constant time: `even[k]`
    is over the first k digits with the ones at an even index doubled, `odd[k]` with the odd ones
    doubled. A stretch that ends before index `stop` doubles every second digit from its right end,
    which are the indexes with the parity of `stop`. One pass over a run, however many stretches
    are then tried, so a long run of small groups costs what its length costs."""
    even, odd = [0], [0]
    for index, char in enumerate(digits):
        digit = int(char)
        even.append(even[-1] + (_fold(digit) if index % 2 == 0 else digit))
        odd.append(odd[-1] + (_fold(digit) if index % 2 == 1 else digit))
    return even, odd


def _card_stretches(run: re.Match[str]) -> list[tuple[int, int]]:
    """Where the card numbers in one run of digits start and end in the text. From each group a
    stretch may start at, the longest one that passes Luhn is taken, and the search goes on after
    it."""
    text = run.string
    groups = [
        (run.start() + m.start(), run.start() + m.end()) for m in DIGIT_GROUP.finditer(run.group())
    ]
    digits = "".join(text[start:end] for start, end in groups)
    if len(digits) < MIN_CARD_DIGITS:
        return []
    even, odd = _luhn_sums(digits)
    offsets = [0]
    for start, end in groups:
        offsets.append(offsets[-1] + end - start)
    found: list[tuple[int, int]] = []
    first = 0
    while first < len(groups):
        begin = offsets[first]
        chosen = None
        # Groups that end before the stretch has 13 digits cannot close a card number.
        enough = max(first, bisect_left(offsets, begin + MIN_CARD_DIGITS) - 1)
        for last in range(enough, len(groups)):
            stop = offsets[last + 1]
            if stop - begin > MAX_CARD_DIGITS:
                break
            sums = even if stop % 2 == 0 else odd
            if stop - begin >= MIN_CARD_DIGITS and (sums[stop] - sums[begin]) % 10 == 0:
                chosen = last
        if chosen is None:
            first += 1
        else:
            found.append((groups[first][0], groups[chosen][1]))
            first = chosen + 1
    return found


def _mask_cards(text: str) -> str:
    pieces: list[str] = []
    position = 0
    for run in DIGIT_RUN.finditer(text):
        for start, end in _card_stretches(run):
            pieces.append(text[position:start])
            pieces.append(CARD_MASK)
            position = end
    pieces.append(text[position:])
    return "".join(pieces)


def mask_patterns(text: str) -> str:
    """The string with every secret-looking pattern replaced. A private key goes first, because
    its body can hold anything the other patterns look for."""
    text = PRIVATE_KEY.sub("[redacted:private-key]", text)
    text = BEARER.sub("Bearer [redacted]", text)
    text = AWS_KEY_ID.sub("[redacted:aws-key-id]", text)
    text = SSN.sub("[redacted:ssn]", text)
    return _mask_cards(text)


def redact_string(text: str) -> str:
    masked = mask_patterns(text)
    if len(text) <= MAX_STRING:
        return masked
    whole = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    return f"{masked[:KEPT_OF_LONG_STRING]}...[sha256:{whole}]"


def _is_secret_key(key: str, config: RedactionConfig) -> bool:
    return bool(SENSITIVE_KEY.search(key)) or key.casefold() in config.keys


def _redact(value: Any, config: RedactionConfig, depth: int) -> Any:
    if depth > MAX_DEPTH:
        return TRUNCATED
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            shown = key if len(key) <= MAX_KEY else key[:MAX_KEY] + TRUNCATED
            out[shown] = (
                REDACTED if _is_secret_key(key, config) else _redact(item, config, depth + 1)
            )
        return out
    if isinstance(value, list | tuple):
        return [_redact(item, config, depth + 1) for item in value]
    return redact_string(str(value))


def redact(arguments: Mapping[str, Any], config: RedactionConfig | None = None) -> dict[str, Any]:
    """The arguments with secrets masked and long strings cut. Numbers, booleans and null stay."""
    result = _redact(arguments, config or RedactionConfig(), 0)
    return result if isinstance(result, dict) else {}


def args_digest(arguments: Mapping[str, Any]) -> str | None:
    """sha256 of the canonical JSON of the arguments as they arrived, hex. None for arguments that
    are not JSON (the pipeline refuses those, and the record is still written)."""
    try:
        return sha256_hex(canonical_json(arguments))
    except Exception:
        return None


def audit_arguments(
    arguments: Mapping[str, Any], config: RedactionConfig | None = None
) -> tuple[dict[str, Any], str | None]:
    """What a record stores of a call's arguments: the redacted form, in the shape jsonb returns
    unchanged and no larger than MAX_REDACTED_BYTES, and the digest of the original."""
    digest = args_digest(arguments)
    try:
        shown = stable_json(redact(arguments, config))
        size = len(canonical_json(shown))
    except Exception:
        return {TRUNCATED: "the arguments could not be shown"}, digest
    if size > MAX_REDACTED_BYTES:
        return {TRUNCATED: f"{size} bytes after redaction"}, digest
    return shown, digest


def is_masked(shown: Any, _depth: int = 0) -> bool:
    """True when arguments in the form `audit_arguments` stores hold anything that was hidden,
    masked or cut. A person who is asked to approve a call reads that form and approves what
    runs, which is the whole of it (KS-691), so they are told when it is not all there.

    It looks for what `redact` leaves behind and so errs toward true: text that happens to hold
    "[redacted" is called masked. It cannot err the other way for a value `redact` changed, which
    the tests in `tests/unit/test_redact.py` hold to for every kind of change.
    """
    if _depth > MAX_DEPTH + 2:
        return True  # deeper than `redact` ever writes, so not a form to vouch for
    if isinstance(shown, str):
        return MASK_MARK in shown or shown == TRUNCATED or CUT_STRING.search(shown) is not None
    if isinstance(shown, Mapping):
        return any(
            str(key).endswith(TRUNCATED) or is_masked(item, _depth + 1)
            for key, item in shown.items()
        )
    if isinstance(shown, list | tuple):
        return any(is_masked(item, _depth + 1) for item in shown)
    return False
