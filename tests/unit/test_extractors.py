"""KS-405: a few arguments of a call, reduced to the typed facts a policy may read."""

from pathlib import Path
from typing import Any

import pytest
import structlog
from structlog.testing import capture_logs

from keystone.policy.extractors import (
    MAX_LONG,
    MIN_LONG,
    ExtractorError,
    check_extractors,
    extract,
    parse_extractor,
)
from keystone.policy.schema_info import ArgField, args_fields
from keystone.registry.config import (
    ConfigError,
    ToolOverride,
    UpstreamConfig,
    apply_config_upstreams,
)

SCHEMA = (Path(__file__).resolve().parents[2] / "policies" / "schema.cedarschema").read_text()
FIELDS = args_fields(SCHEMA)


def one(arguments: dict[str, Any], spec: str) -> int | str | bool | None:
    """The value of a single extractor, or None when the key was left out."""
    return extract(arguments, {"k": spec}).get("k")


@pytest.mark.phase(4)
def test_extract_simple_path() -> None:
    arguments = {
        "amount": 900,
        "account": {"id": "CHK-001", "branches": ["north", "south"]},
        "items": [{"price": 5}, {"price": 7}],
        "urgent": True,
    }

    found = extract(
        arguments,
        {
            "amount": "$.amount",
            "path": "$.account.id",
            "count": "$.items[1].price",
            "recipient_domain": "$.account.branches[0]",
            "flag": "$.urgent",
        },
    )

    assert found == {
        "amount": 900,
        "path": "CHK-001",
        "count": 7,
        "recipient_domain": "north",
        "flag": True,
    }
    assert isinstance(found["flag"], bool)  # a bool stays a bool, not 1


@pytest.mark.phase(4)
def test_extract_domain_pipe() -> None:
    assert extract({"to": "x@evil.test"}, {"recipient_domain": "$.to | domain"}) == {
        "recipient_domain": "evil.test"
    }
    assert one({"to": "Alice@ACME.Test"}, "$.to | domain") == "acme.test"
    assert one({"to": "  bob@acme.test  "}, "$.to | domain") == "acme.test"


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    "recipient",
    [
        "no-at-sign",
        "two@@signs.test",
        "a@evil.test,b@acme.test",  # a list: the last domain must not stand for all of them
        "b@acme.test, a@evil.test",
        "a@acme.test;b@evil.test",
        "Name <a@acme.test>",
        '"a@evil.test"@acme.test',
        "a@",
        "@acme.test",
        "a@acme test",
        "a@exämple.test",
        "",
        7,
        None,
        ["a@acme.test"],
    ],
)
def test_a_recipient_that_is_not_one_plain_address_has_no_domain(recipient: object) -> None:
    # Left out, so a policy that asks "is the domain unknown or external?" asks for approval.
    assert extract({"to": recipient}, {"recipient_domain": "$.to | domain"}) == {}


@pytest.mark.phase(4)
def test_missing_path_omitted() -> None:
    arguments = {"a": {"b": 1}, "list": [1], "text": "x"}

    for spec in ["$.nope", "$.a.nope", "$.a.b.c", "$.list[3]", "$.text[0]", "$.a[0]", "$.list.x"]:
        assert extract(arguments, {"k": spec}) == {}, spec
    # One key that cannot be filled leaves the others alone.
    assert extract(arguments, {"missing": "$.nope", "found": "$.a.b"}) == {"found": 1}


@pytest.mark.phase(4)
def test_the_reason_a_key_was_left_out_is_logged_at_debug() -> None:
    structlog.reset_defaults()  # an earlier test may have set a level that hides debug
    with capture_logs() as logs:
        extract({"amount": "lots"}, {"amount": "$.amount | int", "other": "$.nope"})

    skipped = {
        entry["key"]: entry["why"] for entry in logs if entry["event"] == "extractor_skipped"
    }
    assert skipped == {"amount": "not a number", "other": "no such path"}
    assert {entry["log_level"] for entry in logs} == {"debug"}
    assert "lots" not in str(logs)  # the argument itself is not logged


@pytest.mark.phase(4)
def test_float_amount_to_long() -> None:
    assert extract({"amount": 900.75}, {"amount": "$.amount | int"}) == {"amount": 900}
    assert one({"v": 900}, "$.v | int") == 900
    assert one({"v": -1.9}, "$.v | int") == -1  # toward zero
    assert one({"v": -0.5}, "$.v | int") == 0
    assert one({"v": "42.9"}, "$.v | int") == 42  # an amount sent as text
    assert one({"v": " 7 "}, "$.v | int") == 7


@pytest.mark.phase(4)
def test_cents_multiplies_by_100_and_rounds_half_up() -> None:
    assert one({"v": 900.75}, "$.v | cents") == 90075
    assert one({"v": 500.5}, "$.v | cents") == 50050
    assert one({"v": 0.005}, "$.v | cents") == 1  # half a cent rounds up
    assert one({"v": 1.005}, "$.v | cents") == 101  # no binary float surprise (1.005 * 100)
    assert one({"v": "12.34"}, "$.v | cents") == 1234
    assert one({"v": 3}, "$.v | cents") == 300
    assert one({"v": -2.5}, "$.v | cents") == -250


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    "value", [10**30, 1e30, "1e999999999", float("inf"), "Infinity", 2**63, "9" * 40]
)
def test_a_number_beyond_the_range_of_a_long_saturates(value: object) -> None:
    # Dropping it would skip the rule it exceeds ("approve transfers over 500"), so it is capped.
    assert one({"v": value}, "$.v | int") == MAX_LONG
    assert one({"v": value}, "$.v | cents") == MAX_LONG


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    "value", [-(10**30), -1e30, "-1e999999999", float("-inf"), "-Infinity", -(2**63) - 1]
)
def test_a_very_negative_number_saturates_at_the_bottom(value: object) -> None:
    assert one({"v": value}, "$.v | int") == MIN_LONG


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    "value", [True, False, None, "abc", "", "NaN", float("nan"), [], {}, "1,5", "0x10"]
)
def test_what_is_not_a_number_is_left_out_by_the_numeric_pipes(value: object) -> None:
    assert one({"v": value}, "$.v | int") is None
    assert one({"v": value}, "$.v | cents") is None


@pytest.mark.phase(4)
def test_lower_and_len() -> None:
    assert one({"v": "MiXeD"}, "$.v | lower") == "mixed"
    assert one({"v": "héllo"}, "$.v | len") == 5
    assert one({"v": [1, 2, 3]}, "$.v | len") == 3
    assert one({"v": []}, "$.v | len") == 0
    assert one({"v": 12}, "$.v | lower") is None
    assert one({"v": 12}, "$.v | len") is None
    assert one({"v": {"a": 1}}, "$.v | len") is None


@pytest.mark.phase(4)
def test_pipes_apply_in_order() -> None:
    assert one({"to": "A@B.Test"}, "$.to | domain | lower") == "b.test"
    assert one({"to": "A@B.Test"}, "$.to | domain | len") == 6
    assert one({"v": "Hello"}, "$.v|lower|len") == 5  # spaces are optional
    assert one({"v": 12}, "$.v | len | int") is None  # len of a number has no answer


@pytest.mark.phase(4)
@pytest.mark.parametrize("value", [1.5, [1], {"a": 1}, None])
def test_a_value_with_no_pipe_must_already_be_an_int_a_string_or_a_bool(value: object) -> None:
    assert one({"v": value}, "$.v") is None


@pytest.mark.phase(4)
def test_a_bare_int_beyond_the_range_of_a_long_saturates() -> None:
    assert one({"v": 2**70}, "$.v") == MAX_LONG


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    "spec",
    [
        "",
        "$",
        "a",
        "$a",
        "$.",
        "$..a",
        "$.a.",
        "$.a[",
        "$.a[]",
        "$.a[x]",
        "$.a[-1]",
        "$.a b",
        "$['a']",
        "$.a|",
        "| int",
        "$.a | ",
        "$.a | nope",
        "$.a | INT",
        "$.1a",
        "$.a || int",
    ],
)
def test_a_spec_that_is_not_in_the_language_is_an_error(spec: str) -> None:
    with pytest.raises(ExtractorError):
        parse_extractor(spec)


@pytest.mark.phase(4)
def test_the_schema_args_record_is_read_from_the_shipped_file() -> None:
    assert args_fields(SCHEMA) == {
        "amount": ArgField("amount", "Long", optional=True),
        "recipient_domain": ArgField("recipient_domain", "String", optional=True),
        "path": ArgField("path", "String", optional=True),
        "count": ArgField("count", "Long", optional=True),
    }


@pytest.mark.phase(4)
def test_the_args_record_reader_ignores_comments_and_types_an_extractor_cannot_fill() -> None:
    text = """
    // args: { fake: Long }
    context: {
      args: { a: Long, b?: String, flag?: Bool, tags?: Set<String>, nested?: { x: Long, y: Long },
              // c: Long,
              last: Long },
      other: Long,
    }
    """

    found = args_fields(text)

    assert {name: (f.type, f.optional) for name, f in found.items()} == {
        "a": ("Long", False),
        "b": ("String", True),
        "flag": ("Bool", True),
        "last": ("Long", False),
    }
    assert args_fields("entity Tool;") == {}
    assert args_fields("args: { a: Long") == {}  # an unterminated record gives nothing


@pytest.mark.phase(4)
def test_unknown_key_is_config_error() -> None:
    problems = check_extractors({"to": "$.to", "amount": "$.amount | cents"}, FIELDS)

    [problem] = problems
    assert problem.startswith("extract key 'to' is not an argument the policies can read")
    assert "amount, count, path, recipient_domain" in problem


@pytest.mark.phase(4)
def test_a_spec_that_gives_the_wrong_type_for_its_key_is_a_config_error() -> None:
    problems = check_extractors(
        {
            "amount": "$.to | domain",  # a string for a Long
            "recipient_domain": "$.amount | cents",  # a number for a String
            "path": "$.a | lower",  # fine
            "count": "$.items | len",  # fine
        },
        FIELDS,
    )

    assert len(problems) == 2
    assert any(
        p.startswith("extract key 'amount'") and "Long" in p and "text" in p for p in problems
    )
    assert any(p.startswith("extract key 'recipient_domain'") and "String" in p for p in problems)


@pytest.mark.phase(4)
def test_a_bad_spec_is_reported_with_its_key() -> None:
    [problem] = check_extractors({"amount": "$.amount | nope"}, FIELDS)

    assert problem.startswith("extract key 'amount':") and "nope" in problem


@pytest.mark.phase(4)
def test_a_spec_with_a_free_type_is_accepted_for_any_field() -> None:
    assert check_extractors({"amount": "$.amount", "path": "$.p"}, FIELDS) == []
    assert check_extractors({}, FIELDS) == []


@pytest.mark.phase(4)
async def test_the_config_names_the_upstream_tool_and_key_when_it_stops_startup() -> None:
    upstream = UpstreamConfig(
        id="mail",
        tenant="acme",
        url="http://127.0.0.1:1/mcp",
        tools={"send_email": ToolOverride(extract={"to": "$.to"})},
    )

    with pytest.raises(ConfigError) as raised:
        await apply_config_upstreams(None, [upstream], ["acme"], args=FIELDS)  # type: ignore[arg-type]

    assert "upstream 'mail' tool 'send_email': extract key 'to'" in str(raised.value)
