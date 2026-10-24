"""What a model costs (KS-806): the price list, and the sums that turn tokens into dollars.

`pricing.yaml` maps a model to its prices in dollars for each million tokens:

```yaml
models:
  some-model:
    input_per_mtok: 3.00
    output_per_mtok: 15.00
    cache_read_per_mtok: 0.30      # optional: tokens read from the provider's prompt cache
    cache_write_per_mtok: 3.75     # optional: tokens written to it
  some-family-*:                   # a name ending in * covers every model that starts with it
    input_per_mtok: 1.00
    output_per_mtok: 5.00
```

The prices are the owner's to fill in from the provider's pricing page, and to keep current: nothing
in this repository claims to know them. `pricing.example.yaml` shows the shape with numbers that are
labelled as examples. A model with no entry cannot be called through the proxy, unless
`llm_proxy.allow_unpriced` says it may be and counts as free (and logs a warning).

A cache price that is left out is the input price: a token that a provider read from its cache is
never billed above a fresh one, and pricing it as fresh can only overstate the cost.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from keystone.metering.budgets import money

MILLION = Decimal(1_000_000)
# A token is about four bytes of English text. It is the estimate of the plan (KS-806), and it only
# has to be the right size: the cost that is booked comes from the provider's own count.
BYTES_PER_TOKEN = 4


class PricingError(ValueError):
    """The price list cannot be used. The message says what is wrong with it."""


class ModelPrice(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_per_mtok: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    output_per_mtok: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    cache_read_per_mtok: Decimal | None = Field(default=None, ge=0, max_digits=18, decimal_places=9)
    cache_write_per_mtok: Decimal | None = Field(
        default=None, ge=0, max_digits=18, decimal_places=9
    )


class PriceFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    models: dict[str, ModelPrice]

    @field_validator("models")
    @classmethod
    def _names(cls, models: dict[str, ModelPrice]) -> dict[str, ModelPrice]:
        for name in models:
            if not name or name != name.strip():
                raise ValueError(f"{name!r} is not a model name")
            if name == "*" or "*" in name[:-1]:
                raise ValueError(
                    f"{name!r}: a * may only end a name, as in some-family-*, and not stand alone"
                )
        return models


@dataclass(frozen=True)
class Usage:
    """What a request used. `input_tokens` are the tokens that were not read from or written to a
    cache; the cache tokens are counted apart, because they are priced apart."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total_input(self) -> int:
        return self.input_tokens + self.cache_read_tokens + self.cache_write_tokens


class PriceList:
    def __init__(self, models: Mapping[str, ModelPrice]) -> None:
        self._exact = {name: price for name, price in models.items() if not name.endswith("*")}
        # Longest prefix first, so that the most specific name wins.
        self._prefixes = sorted(
            ((name[:-1], name, price) for name, price in models.items() if name.endswith("*")),
            key=lambda item: -len(item[0]),
        )

    @classmethod
    def load(cls, path: Path) -> PriceList:
        try:
            text = path.read_text()
        except OSError as error:
            reason = error.strerror or type(error).__name__
            raise PricingError(
                f"the pricing file {path} cannot be read ({reason}). "
                "Copy pricing.example.yaml and fill in the prices from your provider"
            ) from None
        try:
            loaded = yaml.safe_load(text)
            if loaded is None:
                raise PricingError(f"the pricing file {path} lists no model")
            parsed = PriceFile.model_validate(loaded)
        except (yaml.YAMLError, ValidationError) as error:
            if isinstance(error, ValidationError):
                problems = "; ".join(
                    f"{'.'.join(str(part) for part in e['loc'])}: {e['msg']}"
                    for e in error.errors()
                )
            else:
                problems = "it is not valid YAML"
            raise PricingError(f"the pricing file {path} is not usable: {problems}") from None
        if not parsed.models:
            raise PricingError(f"the pricing file {path} lists no model")
        return cls(parsed.models)

    def known(self) -> frozenset[str]:
        """The names the file lists, patterns included: the labels a metric may carry."""
        return frozenset(self._exact) | frozenset(name for _, name, _ in self._prefixes)

    def match(self, model: str) -> tuple[str, ModelPrice] | None:
        """The entry for a model, by its name in the file: the exact name, or else the longest
        pattern that covers it."""
        if model in self._exact:
            return model, self._exact[model]
        for prefix, name, price in self._prefixes:
            if model.startswith(prefix):
                return name, price
        return None

    def price_of(self, model: str) -> ModelPrice | None:
        found = self.match(model)
        return found[1] if found else None


def cost(price: ModelPrice, usage: Usage) -> Decimal:
    """The dollars a request cost, from the provider's own count of its tokens."""
    read = (
        price.cache_read_per_mtok if price.cache_read_per_mtok is not None else price.input_per_mtok
    )
    write = (
        price.cache_write_per_mtok
        if price.cache_write_per_mtok is not None
        else price.input_per_mtok
    )
    total = (
        usage.input_tokens * price.input_per_mtok
        + usage.output_tokens * price.output_per_mtok
        + usage.cache_read_tokens * read
        + usage.cache_write_tokens * write
    )
    return money(total / MILLION)


def estimate(price: ModelPrice, body_bytes: int, max_tokens: int) -> Decimal:
    """The most a request could cost before it is made: its body at four bytes a token as input,
    and `max_tokens` of output, which is the longest the model may answer. The budget is checked
    against this because the real count is not known until the end."""
    tokens = math.ceil(body_bytes / BYTES_PER_TOKEN)
    return money((tokens * price.input_per_mtok + max_tokens * price.output_per_mtok) / MILLION)
