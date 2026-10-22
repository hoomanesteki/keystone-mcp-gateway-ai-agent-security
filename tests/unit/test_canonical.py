from datetime import UTC, datetime, timedelta, timezone

import pytest

from keystone.core.canonical import canonical_json, sha256_hex


@pytest.mark.phase(1)
def test_canonical_json_stable() -> None:
    a = {"b": 1, "a": {"y": [1, 2], "x": "é"}, "c": None}
    b = {"c": None, "a": {"x": "é", "y": [1, 2]}, "b": 1}

    assert canonical_json(a) == canonical_json(b)
    assert canonical_json(a) == '{"a":{"x":"é","y":[1,2]},"b":1,"c":null}'.encode()


@pytest.mark.phase(1)
def test_datetimes_are_utc_with_z() -> None:
    plus_two = datetime(2026, 1, 2, 5, 4, 5, tzinfo=timezone(timedelta(hours=2)))
    utc = datetime(2026, 1, 2, 3, 4, 5, 500000, tzinfo=UTC)

    assert canonical_json({"t": plus_two}) == b'{"t":"2026-01-02T03:04:05Z"}'
    assert canonical_json({"t": utc}) == b'{"t":"2026-01-02T03:04:05.500000Z"}'


@pytest.mark.phase(1)
def test_naive_datetime_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone"):
        canonical_json({"t": datetime(2026, 1, 2, 3, 4, 5)})


@pytest.mark.phase(1)
def test_sets_become_sorted_lists() -> None:
    assert canonical_json({"tags": {"b", "a"}}) == b'{"tags":["a","b"]}'
    assert canonical_json({"tags": frozenset({"z", "m"})}) == b'{"tags":["m","z"]}'


@pytest.mark.phase(1)
def test_unsupported_values_raise() -> None:
    with pytest.raises(TypeError):
        canonical_json({"x": object()})
    with pytest.raises(ValueError, match="Out of range"):
        canonical_json({"x": float("nan")})


@pytest.mark.phase(1)
def test_sha256_hex() -> None:
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
