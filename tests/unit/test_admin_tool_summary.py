"""KS-608: the tool list tells the console what a call to each tool costs."""

from decimal import Decimal

import pytest

from keystone.admin.api import _summary
from keystone.db.models import Tool

pytestmark = pytest.mark.phase(6)


def tool(cost: Decimal) -> Tool:
    return Tool(
        tenant_id="acme",
        name="mail__send_email",
        upstream_id="mail",
        upstream_tool_name="send_email",
        description="Send an email.",
        input_schema={"type": "object"},
        risk="high",
        tags=["external_effect"],
        cost_per_call_usd=cost,
        timeout_s=30.0,
        extractors={},
        description_hash="d",
        schema_hash="s",
        status="active",
    )


@pytest.mark.parametrize(
    ("cost", "text"),
    [
        (Decimal(0), "0"),
        # What the registry stores for a price of 0.0, and for a price of 100.
        (Decimal("0.0"), "0"),
        (Decimal("1E+2"), "100"),
        (Decimal("0.0023"), "0.0023"),
        # A small price must not come out as 1E-7, which a console would read as text.
        (Decimal("1E-7"), "0.0000001"),
        (Decimal("12.50"), "12.5"),
    ],
)
def test_the_price_is_a_plain_decimal_string(cost: Decimal, text: str) -> None:
    assert _summary(tool(cost)).cost_per_call_usd == text
