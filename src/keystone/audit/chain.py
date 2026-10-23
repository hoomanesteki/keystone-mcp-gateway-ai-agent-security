"""The hash chain over audit records (ADR-0009).

A record's hash is sha256 of the previous record's hash, as bytes, followed by the canonical JSON
of the record's own columns. Changing a record changes its hash and breaks the link in the record
after it; removing a record breaks the same link. `keystone audit verify` recomputes the chain
from the rows it reads back from Postgres, so the writer must hash exactly what a SELECT returns.
Three things differ between a Python value and the value Postgres hands back, and each is settled
here, before the hash is computed and before the row is stored:

- Timestamps are UTC at microsecond precision, written as one fixed-width string.
- Numbers that are money, scores or durations are Decimals with a fixed number of places. A float
  would read back from a `numeric` column as something else.
- JSON goes through `stable_json`: jsonb keeps numbers as `numeric`, so a float such as 1e22 comes
  back as an integer, and a string cannot hold a NUL character.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation, localcontext
from typing import Any, Literal

from keystone.core.canonical import canonical_json
from keystone.core.errors import Reject
from keystone.core.types import CallContext

Outcome = Literal["ok", "rejected", "error"]

GENESIS = "0" * 64

# The columns the hash covers, in table order: every column except seq, prev_hash and hash.
HASHED_COLUMNS = (
    "ts",
    "call_id",
    "tenant_id",
    "user_id",
    "agent_id",
    "session_id",
    "tool_name",
    "effect",
    "decision_source",
    "reasons",
    "policy_version",
    "outcome",
    "reject_code",
    "dispatched",
    "args_redacted",
    "args_digest",
    "scan_score",
    "scan_action",
    "cost_usd",
    "latency_ms",
    "trace_id",
)

# Places kept for each decimal column. Postgres stores the `numeric` as given, so the writer
# quantizes first and the hash and the row agree.
DECIMAL_SCALES: dict[str, Decimal] = {
    "scan_score": Decimal("0.000001"),
    "cost_usd": Decimal("0.00000001"),
    "latency_ms": Decimal("0.001"),
}

MAX_JSON_DEPTH = 32
TRUNCATED = "[truncated]"
NUL_TEXT = "\\u0000"
# Enough digits for any cost a float can hold, with the places above.
DECIMAL_PRECISION = 60


def clean_text(text: str) -> str:
    """Text Postgres can store: no NUL character, and no lone surrogate (which is not UTF-8)."""
    if "\x00" in text:
        text = text.replace("\x00", NUL_TEXT)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = text.encode("utf-8", "replace").decode("utf-8")
    return text


def format_ts(moment: datetime) -> str:
    """UTC, always six fractional digits. A naive time is taken as UTC, because an audit record
    must not fail to be written over a missing zone."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def utc_micros(moment: datetime) -> datetime:
    """The value to store in a timestamptz column: UTC, microseconds, which is what the column
    keeps and what a datetime holds."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def to_decimal(value: object, scale: Decimal) -> Decimal | None:
    """`value` as a Decimal rounded to `scale`, or None when it is None, not a finite number, or
    too large to hold. A float goes through its shortest repr, so 0.1 is 0.1 and not the binary
    value nearest to it."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = Decimal(repr(value)) if isinstance(value, float) else Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    if not number.is_finite():
        return None
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        try:
            rounded = number.quantize(scale, rounding=ROUND_HALF_EVEN)
        except InvalidOperation:
            return None
    # Postgres has no negative zero, so a stored -0.000 comes back as 0.000.
    return abs(rounded) if rounded == 0 else rounded


def stable_float(value: float) -> int | float | str:
    """A float in the form jsonb returns unchanged. Postgres prints a numeric without an
    exponent, so a float whose digits have no fraction (1e22) is read back as an integer."""
    if not math.isfinite(value):
        return str(value)
    if value == 0:
        return 0.0  # jsonb has no negative zero
    plain = format(Decimal(repr(value)), "f")
    return float(plain) if "." in plain else int(plain)


def stable_json(value: Any, _depth: int = 0) -> Any:
    """`value` as JSON that survives a round trip through jsonb: strings Postgres can store,
    numbers in the form it returns, keys as strings. Anything that is not JSON becomes its text,
    and nesting deeper than MAX_JSON_DEPTH is cut."""
    if _depth > MAX_JSON_DEPTH:
        return TRUNCATED
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return stable_float(value)
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, Mapping):
        return {clean_text(str(k)): stable_json(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [stable_json(item, _depth + 1) for item in value]
    return clean_text(str(value))


def _canonical_value(name: str, value: Any) -> Any:
    if isinstance(value, datetime):
        return format_ts(value)
    scale = DECIMAL_SCALES.get(name)
    if scale is not None:
        number = to_decimal(value, scale)
        return None if number is None else format(number, "f")
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, tuple):
        return list(value)
    return value


def canonical_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """The columns as JSON-ready values: timestamps and decimals as strings, nothing else
    changed. Applying it to a value it already produced changes nothing."""
    return {name: _canonical_value(name, value) for name, value in fields.items()}


def compute_hash(prev_hash: str, fields: Mapping[str, Any]) -> str:
    """sha256(bytes.fromhex(prev_hash) + canonical_json(fields)), as hex."""
    digest = hashlib.sha256(bytes.fromhex(prev_hash))
    digest.update(canonical_json(canonical_fields(fields)))
    return digest.hexdigest()


def fields_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """The hashed columns of a row read back from the table."""
    return {name: row[name] for name in HASHED_COLUMNS}


def record_fields(
    ctx: CallContext,
    outcome: Outcome,
    reject: Reject | None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Every column of the record except seq, prev_hash and hash, ready to store and to hash.

    It reads the context once, when the call has finished, so the queue holds a snapshot that a
    later change to the context cannot reach.
    """
    decision = ctx.decision
    reasons = [clean_text(str(r)) for r in decision.reasons] if decision else []
    # A refusal that made no decision (a quarantined tool, an audit log that is down) names its
    # reason in the rejection, so a search of the log finds it.
    named = reject.data.get("keystone/reason") if reject else None
    if isinstance(named, str) and named not in reasons:
        reasons.append(clean_text(named))
    received = utc_micros(ctx.received_at)
    finished = utc_micros(now) if now else datetime.now(UTC)
    elapsed_ms = max(0.0, (finished - received).total_seconds() * 1000)
    scan = ctx.scan
    cost = to_decimal(ctx.cost_usd, DECIMAL_SCALES["cost_usd"])
    return {
        "ts": received,
        "call_id": clean_text(ctx.call_id),
        "tenant_id": clean_text(ctx.principal.tenant_id),
        "user_id": clean_text(ctx.principal.user_id),
        "agent_id": clean_text(ctx.principal.agent_id),
        "session_id": clean_text(ctx.session.session_id),
        "tool_name": clean_text(ctx.tool.name),
        "effect": decision.effect.value if decision else None,
        "decision_source": decision.source if decision else None,
        "reasons": reasons,
        "policy_version": clean_text(decision.policy_version)
        if decision and decision.policy_version
        else None,
        "outcome": outcome,
        "reject_code": reject.code.value if reject else None,
        "dispatched": ctx.dispatched,
        # Arguments arrive with KS-502, redacted, with a digest of the original.
        "args_redacted": None,
        "args_digest": None,
        "scan_score": to_decimal(scan.score, DECIMAL_SCALES["scan_score"]) if scan else None,
        "scan_action": scan.action if scan else None,
        "cost_usd": cost if cost is not None else Decimal(0).quantize(DECIMAL_SCALES["cost_usd"]),
        "latency_ms": to_decimal(elapsed_ms, DECIMAL_SCALES["latency_ms"]),
        "trace_id": None,
    }
