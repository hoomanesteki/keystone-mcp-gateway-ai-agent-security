"""The hash chain: how a record becomes bytes and a hash (ADR-0009)."""

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from keystone.audit.chain import (
    GENESIS,
    HASHED_COLUMNS,
    canonical_fields,
    clean_text,
    compute_hash,
    record_fields,
    stable_json,
    to_decimal,
)
from keystone.core.canonical import canonical_json
from keystone.core.errors import Code, Reject
from keystone.core.types import Decision, Effect, ScanResult
from tests.fixtures.calls import make_ctx

MOMENT = datetime(2026, 10, 22, 12, 30, 5, 123456, tzinfo=UTC)


def sample() -> dict[str, object]:
    return {
        "ts": MOMENT,
        "call_id": "01JTESTCALL",
        "tenant_id": "acme",
        "reasons": ["same-tenant-low-medium"],
        "cost_usd": Decimal("0.01000000"),
        "dispatched": True,
    }


@pytest.mark.phase(5)
def test_hash_deterministic() -> None:
    fields = sample()

    first = compute_hash(GENESIS, fields)

    assert first == compute_hash(GENESIS, fields)
    assert len(first) == 64 and set(first) <= set("0123456789abcdef")
    # The key order of the dict is not part of the hash.
    assert first == compute_hash(GENESIS, dict(reversed(list(fields.items()))))
    # The rule written out: sha256 of the previous hash as bytes, then the canonical JSON.
    text = (
        '{"call_id":"01JTESTCALL","cost_usd":"0.01000000","dispatched":true,'
        '"reasons":["same-tenant-low-medium"],"tenant_id":"acme",'
        '"ts":"2026-10-22T12:30:05.123456Z"}'
    )
    assert first == hashlib.sha256(bytes.fromhex(GENESIS) + text.encode()).hexdigest()
    # Anything that differs changes the hash: the link, and each field.
    assert compute_hash("1" * 64, fields) != first
    for name, other in [
        ("call_id", "01JOTHER"),
        ("reasons", ["default-deny"]),
        ("dispatched", False),
        ("ts", MOMENT + timedelta(microseconds=1)),
    ]:
        assert compute_hash(GENESIS, {**fields, name: other}) != first, name


@pytest.mark.phase(5)
def test_a_moment_hashes_the_same_in_any_zone() -> None:
    elsewhere = MOMENT.astimezone(timezone(timedelta(hours=5, minutes=30)))

    assert compute_hash(GENESIS, {"ts": elsewhere}) == compute_hash(GENESIS, {"ts": MOMENT})
    # Whole seconds still print six fractional digits, so the width never changes the hash.
    assert canonical_fields({"ts": MOMENT.replace(microsecond=0)}) == {
        "ts": "2026-10-22T12:30:05.000000Z"
    }


@pytest.mark.phase(5)
def test_money_hashes_as_a_fixed_number_of_places() -> None:
    # A float and the Decimal a numeric column returns for it give one hash, and so do scales.
    sums = 0.1 + 0.2
    stored = to_decimal(sums, Decimal("0.00000001"))

    assert stored == Decimal("0.30000000")
    assert str(stored) == "0.30000000"
    one = compute_hash(GENESIS, {"cost_usd": sums})
    assert one == compute_hash(GENESIS, {"cost_usd": stored})
    assert one == compute_hash(GENESIS, {"cost_usd": Decimal("0.3")})
    assert one == compute_hash(GENESIS, {"cost_usd": Decimal("0.300000000000")})
    assert canonical_fields({"cost_usd": 0.0}) == {"cost_usd": "0.00000000"}
    assert canonical_fields({"cost_usd": Decimal("-0.00")}) == {"cost_usd": "0.00000000"}


@pytest.mark.phase(5)
@pytest.mark.parametrize("value", [None, True, float("nan"), float("inf"), "x", Decimal("NaN")])
def test_a_number_that_is_not_a_number_is_stored_as_null(value: object) -> None:
    assert to_decimal(value, Decimal("0.001")) is None
    assert canonical_fields({"latency_ms": value}) == {"latency_ms": None}


@pytest.mark.phase(5)
def test_an_enormous_cost_does_not_raise() -> None:
    assert to_decimal(1e300, Decimal("0.00000001")) is None
    assert to_decimal(10**20, Decimal("0.00000001")) == Decimal("100000000000000000000.00000000")


@pytest.mark.phase(5)
def test_stable_json_returns_numbers_the_way_jsonb_does() -> None:
    # Postgres stores a JSON number as a numeric and prints it without an exponent, so a float
    # with no fraction comes back as an integer, and negative zero as zero.
    value = stable_json({"big": 1e22, "plain": 5.0, "small": 1.5e-7, "zero": -0.0, "n": 7})

    assert value == {"big": 10**22, "plain": 5.0, "small": 1.5e-7, "zero": 0.0, "n": 7}
    assert isinstance(value["big"], int) and isinstance(value["plain"], float)
    assert canonical_json(value) == (
        b'{"big":10000000000000000000000,"n":7,"plain":5.0,"small":1.5e-07,"zero":0.0}'
    )
    assert stable_json([float("nan"), float("-inf")]) == ["nan", "-inf"]


@pytest.mark.phase(5)
def test_stable_json_makes_text_postgres_can_store() -> None:
    assert clean_text("a\x00b") == "a\\u0000b"
    assert clean_text("ok é \U0001f600") == "ok é \U0001f600"
    assert clean_text("lone \ud800 surrogate") == "lone ? surrogate"
    cleaned = stable_json({"k\x00ey": ["v\x00", {1: "int key"}], "n": None, "t": (1, 2)})
    assert cleaned == {"k\\u0000ey": ["v\\u0000", {"1": "int key"}], "n": None, "t": [1, 2]}
    json.dumps(cleaned).encode("utf-8")  # encodes, so the driver can send it


@pytest.mark.phase(5)
def test_stable_json_cuts_nesting_that_is_too_deep() -> None:
    deep: object = "leaf"
    for _ in range(100):
        deep = [deep]

    cut = stable_json(deep)

    assert "[truncated]" in json.dumps(cut)
    assert len(canonical_json(cut)) < 400  # and canonical_json does not hit the recursion limit


@pytest.mark.phase(5)
def test_a_record_covers_every_hashed_column() -> None:
    fields = record_fields(make_ctx(), "ok", None)

    assert tuple(fields) == HASHED_COLUMNS
    assert "seq" not in fields and "prev_hash" not in fields and "hash" not in fields


@pytest.mark.phase(5)
def test_a_record_names_the_decision_the_refusal_and_the_reason() -> None:
    ctx = make_ctx(
        decision=Decision(
            effect=Effect.DENY, reasons=["default-deny"], source="policy", policy_version="v1"
        ),
        scan=ScanResult(score=0.123456789, label="benign", action="pass"),
        cost_usd=0.5,
        dispatched=False,
    )
    refusal = Reject(Code.DENIED, "no", {"keystone/reason": "audit-unavailable"})

    fields = record_fields(ctx, "rejected", refusal, now=ctx.received_at + timedelta(seconds=2))

    assert (fields["effect"], fields["decision_source"], fields["policy_version"]) == (
        "deny",
        "policy",
        "v1",
    )
    assert fields["outcome"] == "rejected"
    assert fields["reasons"] == ["default-deny", "audit-unavailable"]
    assert fields["reject_code"] == "KS_DENIED"
    assert fields["dispatched"] is False
    assert fields["scan_score"] == Decimal("0.123457")
    assert fields["scan_action"] == "pass"
    assert fields["cost_usd"] == Decimal("0.50000000")
    assert fields["latency_ms"] == Decimal("2000.000")
    assert fields["ts"] == ctx.received_at


@pytest.mark.phase(5)
def test_a_call_without_a_decision_has_null_effect_and_no_reasons() -> None:
    fields = record_fields(make_ctx(), "error", None)

    assert fields["effect"] is None and fields["decision_source"] is None
    assert fields["policy_version"] is None
    assert fields["reasons"] == [] and fields["reject_code"] is None
    assert fields["scan_score"] is None and fields["cost_usd"] == Decimal("0.00000000")
    assert fields["tenant_id"] == "acme" and fields["user_id"] == "olivia"


@pytest.mark.phase(5)
def test_a_record_never_holds_text_the_database_would_refuse() -> None:
    ctx = make_ctx(decision=Decision(effect=Effect.ALLOW, reasons=["a\x00b"], source="policy"))

    fields = record_fields(ctx, "ok", None)

    assert fields["reasons"] == ["a\\u0000b"]
    assert "\x00" not in json.dumps(fields, default=str)
