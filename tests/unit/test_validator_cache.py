"""KS-992: the validator of an input schema is built once for each schema hash."""

from typing import Any

import pytest
from jsonschema import Draft202012Validator

from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext
from keystone.gateway import pipeline
from keystone.gateway.pipeline import validate_arguments
from tests.fixtures.calls import make_ctx, make_tool

pytestmark = pytest.mark.phase(9)

SCHEMA = {"type": "object", "properties": {"n": {"type": "integer"}}, "required": ["n"]}


@pytest.fixture(autouse=True)
def empty_cache() -> None:
    pipeline._validators.clear()


def ctx_for(
    schema: dict[str, Any], arguments: dict[str, Any], schema_hash: str = "h1"
) -> CallContext:
    tool = make_tool(schema=schema).model_copy(update={"schema_hash": schema_hash})
    return make_ctx(arguments, tool=tool)


def test_a_second_call_uses_the_validator_of_the_first(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[int] = []
    real = Draft202012Validator

    def counting(schema: dict[str, Any]) -> Any:
        built.append(1)
        return real(schema)

    monkeypatch.setattr(pipeline, "Draft202012Validator", counting)

    validate_arguments(ctx_for(SCHEMA, {"n": 1}))
    validate_arguments(ctx_for(SCHEMA, {"n": 2}))
    with pytest.raises(Reject) as refused:
        validate_arguments(ctx_for(SCHEMA, {"n": "x"}))

    assert built == [1]
    assert refused.value.code is Code.INVALID_ARGUMENTS


def test_a_hash_that_does_not_match_its_schema_never_validates_against_another() -> None:
    validate_arguments(ctx_for(SCHEMA, {"n": 1}, "same"))
    other = {"type": "object", "properties": {"s": {"type": "string"}}, "required": ["s"]}

    with pytest.raises(Reject):
        validate_arguments(ctx_for(other, {"n": 1}, "same"))
    validate_arguments(ctx_for(other, {"s": "a"}, "same"))


def test_a_tool_without_a_hash_is_not_kept() -> None:
    validate_arguments(ctx_for(SCHEMA, {"n": 1}, ""))
    assert pipeline._validators == {}


def test_the_cache_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pipeline, "MAX_VALIDATORS", 3)
    for index in range(10):
        validate_arguments(ctx_for(SCHEMA, {"n": 1}, f"h{index}"))
    assert list(pipeline._validators) == ["h7", "h8", "h9"]
