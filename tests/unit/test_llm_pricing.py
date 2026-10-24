"""KS-806: the price list and the sums that turn tokens into dollars."""

from decimal import Decimal
from pathlib import Path

import pytest

from keystone.metering.pricing import (
    ModelPrice,
    PriceList,
    PricingError,
    Usage,
    cost,
    estimate,
)

pytestmark = pytest.mark.phase(8)

ROOT = Path(__file__).resolve().parents[2]


def price(
    i: str = "3", o: str = "15", read: str | None = None, write: str | None = None
) -> ModelPrice:
    return ModelPrice(
        input_per_mtok=Decimal(i),
        output_per_mtok=Decimal(o),
        cache_read_per_mtok=None if read is None else Decimal(read),
        cache_write_per_mtok=None if write is None else Decimal(write),
    )


def test_a_million_tokens_cost_the_price_per_million() -> None:
    assert cost(price("3", "15"), Usage(input_tokens=1_000_000)) == Decimal("3")
    assert cost(price("3", "15"), Usage(output_tokens=1_000_000)) == Decimal("15")


def test_cost_adds_input_and_output_at_their_own_prices() -> None:
    # 4 tokens in at $3 and 12 out at $15 a million: 12 + 180 millionths of a dollar.
    assert cost(price(), Usage(input_tokens=4, output_tokens=12)) == Decimal("0.000192")


def test_cache_tokens_have_prices_of_their_own() -> None:
    usage = Usage(input_tokens=4, output_tokens=12, cache_read_tokens=5, cache_write_tokens=2)

    got = cost(price("3", "15", read="0.30", write="3.75"), usage)

    # 12 + 180 + 5 * 0.30 + 2 * 3.75 = 201 millionths.
    assert got == Decimal("0.000201")


def test_a_cache_price_that_is_left_out_is_the_input_price() -> None:
    usage = Usage(input_tokens=4, cache_read_tokens=5, cache_write_tokens=2)

    assert cost(price("3", "15"), usage) == Decimal("0.000033")  # 11 tokens at $3


def test_the_cost_of_nothing_is_nothing_and_a_free_model_is_free() -> None:
    assert cost(price(), Usage()) == 0
    assert cost(price("0", "0"), Usage(input_tokens=10**9, output_tokens=10**9)) == 0


def test_the_cost_is_kept_to_nine_decimal_places() -> None:
    assert cost(price("0.0000001", "0"), Usage(input_tokens=1)) == Decimal("0")
    assert cost(price("1", "0"), Usage(input_tokens=1)) == Decimal("0.000001")


def test_all_input_counts_the_cache_tokens_too() -> None:
    assert Usage(input_tokens=4, cache_read_tokens=5, cache_write_tokens=2).total_input == 11


def test_the_estimate_is_the_body_at_four_bytes_a_token_plus_the_longest_answer() -> None:
    # 401 bytes is 101 tokens (rounded up) at $3, and 100 tokens may come back at $15.
    assert estimate(price(), 401, 100) == Decimal("0.001803")
    assert estimate(price(), 0, 0) == 0


def test_the_estimate_is_never_below_what_the_request_can_cost() -> None:
    p = price("3", "15", read="0.3", write="3.75")
    # A request of 800 bytes that is answered with its full 50 tokens, all of it fresh input.
    worst = cost(p, Usage(input_tokens=200, output_tokens=50))

    assert estimate(p, 800, 50) >= worst


def test_a_model_is_found_by_its_exact_name() -> None:
    listed = PriceList({"fake-model": price("1", "2"), "other": price("5", "6")})

    assert listed.price_of("fake-model") == price("1", "2")
    assert listed.price_of("fake-model-2") is None
    assert listed.price_of("") is None


def test_a_name_that_ends_in_a_star_covers_every_model_that_starts_with_it() -> None:
    listed = PriceList({"family-*": price("1", "2"), "family-big-*": price("9", "9")})

    assert listed.price_of("family-small-1") == price("1", "2")
    # The longest pattern wins, and an exact name wins over both.
    assert listed.price_of("family-big-2") == price("9", "9")
    assert listed.price_of("elsewhere") is None
    assert PriceList({"family-*": price(), "family-x": price("7", "7")}).price_of(
        "family-x"
    ) == price("7", "7")


def test_the_name_in_the_file_is_what_a_metric_may_carry() -> None:
    listed = PriceList({"a": price(), "family-*": price()})

    assert listed.known() == {"a", "family-*"}
    assert listed.match("family-7") is not None and listed.match("family-7")[0] == "family-*"  # type: ignore[index]


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "pricing.yaml"
    path.write_text(text)
    return path


def test_a_price_file_loads(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        "models:\n"
        "  fake-model: {input_per_mtok: 3.0, output_per_mtok: 15}\n"
        "  fake-cached: {input_per_mtok: 3, output_per_mtok: 15, cache_read_per_mtok: 0.3}\n",
    )

    listed = PriceList.load(path)

    assert listed.price_of("fake-model") == price("3.0", "15")
    assert listed.price_of("fake-cached") == price("3", "15", read="0.3")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "lists no model"),
        ("models: {}\n", "lists no model"),
        ("models: [a, b]\n", "models"),
        ("models:\n  m: {input_per_mtok: 3}\n", "output_per_mtok"),
        ("models:\n  m: {input_per_mtok: -1, output_per_mtok: 1}\n", "input_per_mtok"),
        ("models:\n  m: {input_per_mtok: 1, output_per_mtok: 1, cache: 2}\n", "cache"),
        ("models:\n  m*x: {input_per_mtok: 1, output_per_mtok: 1}\n", "may only end a name"),
        ("models:\n  '*': {input_per_mtok: 1, output_per_mtok: 1}\n", "stand alone"),
        ("surprise: 1\nmodels:\n  m: {input_per_mtok: 1, output_per_mtok: 1}\n", "surprise"),
        ("models: {m: {input_per_mtok: x, output_per_mtok: 1}}\n", "input_per_mtok"),
        ("models: [unclosed\n", "not valid YAML"),
    ],
)
def test_a_price_file_that_cannot_be_used_says_why(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(PricingError, match=message):
        PriceList.load(write(tmp_path, text))


def test_a_price_file_that_is_not_there_says_what_to_do(tmp_path: Path) -> None:
    with pytest.raises(PricingError, match=r"pricing\.example\.yaml"):
        PriceList.load(tmp_path / "nope.yaml")


def test_the_example_file_loads_and_says_that_its_prices_are_not_real() -> None:
    path = ROOT / "pricing.example.yaml"

    listed = PriceList.load(path)

    text = path.read_text().lower()
    assert listed.known()
    assert "example" in text and "not real" in text
    assert "fill in" in text and "pricing page" in text


def test_the_compose_prices_are_fake_ones_for_fake_models() -> None:
    path = ROOT / "deploy" / "pricing.compose.yaml"

    listed = PriceList.load(path)

    assert listed.known() and all(name.startswith("fake-") for name in listed.known())
    assert "fake" in path.read_text().lower()
