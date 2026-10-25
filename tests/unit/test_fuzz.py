"""KS-906: properties that must hold for any input, not only the ones I thought of.

Each test runs 500 examples. The generators produce arbitrary JSON, because that is all a client
or an upstream can send; a failure here is a crash or an unstable digest on some value nobody
wrote a case for.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from keystone.audit.redact import redact
from keystone.core.canonical import canonical_json
from keystone.core.types import ToolResult
from keystone.defense.scanner import extract as extract_result
from keystone.policy.extractors import extract as extract_arguments
from keystone.registry.naming import make_tool_name, split_tool_name

EXAMPLES = 500
FUZZ = settings(
    max_examples=EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

# Text with the awkward parts of Unicode left in: surrogates are not UTF-8, so they cannot arrive
# in a JSON body, but controls, combining marks and astral characters can.
TEXT = st.text(alphabet=st.characters(blacklist_categories=["Cs"]), max_size=60)
# Things that look like what redact looks for, so the patterns are hit far more often than random
# text would hit them.
SECRETISH = st.sampled_from(
    [
        "4111 1111 1111 1111",
        "123-45-6789",
        "Bearer abcdefghijklmnop",
        "AKIAABCDEFGHIJKLMNOP",
        "-----BEGIN RSA PRIVATE KEY-----\nabc",
        "x" * 3000,
    ]
)
SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**30), max_value=10**30),
    st.floats(allow_nan=False, allow_infinity=False),
    TEXT,
    SECRETISH,
)
KEYS = st.one_of(TEXT, st.sampled_from(["password", "api_key", "Authorization", "to", "amount"]))
JSON = st.recursive(
    SCALARS,
    lambda inner: st.one_of(st.lists(inner, max_size=5), st.dictionaries(KEYS, inner, max_size=5)),
    max_leaves=40,
)
OBJECTS = st.dictionaries(KEYS, JSON, max_size=6)

SPECS = [
    "$.amount",
    "$.amount | int",
    "$.amount | cents",
    "$.to | domain",
    "$.to | lower",
    "$.items | len",
    "$.a.b.c",
    "$.items[0].price | int",
    "$.items[*].price",
]


@pytest.mark.phase(9)
@FUZZ
@given(arguments=OBJECTS)
def test_fuzz_extractors_never_raise(arguments: dict[str, Any]) -> None:
    for spec in SPECS:
        found = extract_arguments(arguments, {"k": spec})
        assert set(found) <= {"k"}
        assert all(isinstance(v, bool | int | str) for v in found.values())


@pytest.mark.phase(9)
@FUZZ
@given(
    blocks=st.lists(st.one_of(JSON, st.dictionaries(KEYS, JSON, max_size=4)), max_size=5),
    structured=st.one_of(st.none(), OBJECTS),
    kinds=st.lists(
        st.sampled_from(["text", "image", "resource", "resource_link", None]), max_size=5
    ),
)
def test_fuzz_result_extractor_never_raises(
    blocks: list[Any], structured: dict[str, Any] | None, kinds: list[str | None]
) -> None:
    content = [
        {"type": kind, "text": block, "resource": block, "name": block, "title": block}
        if kind
        else block
        for kind, block in zip(kinds, blocks, strict=False)
    ]
    # The model accepts only dict blocks; anything else is the SDK's to refuse before this point.
    content = [c for c in content if isinstance(c, dict)]
    extracted = extract_result(ToolResult(content=content, structured_content=structured))
    assert isinstance(extracted.text, str)
    assert extracted.images_skipped >= 0


@pytest.mark.phase(9)
@FUZZ
@given(arguments=OBJECTS)
def test_fuzz_redact_idempotent(arguments: dict[str, Any]) -> None:
    once = redact(arguments)
    assert redact(once) == once


@pytest.mark.phase(9)
@FUZZ
@given(arguments=OBJECTS)
def test_fuzz_redact_never_keeps_a_secret_key_value(arguments: dict[str, Any]) -> None:
    shown = redact({"password": arguments, "api_key": "k-123456"})
    assert shown["password"] == "[redacted]"
    assert shown["api_key"] == "[redacted]"


@pytest.mark.phase(9)
@FUZZ
@given(value=JSON)
def test_fuzz_canonical_json_stable(value: Any) -> None:
    first = canonical_json(value)
    assert canonical_json(json.loads(first)) == first


@pytest.mark.phase(9)
@FUZZ
@given(data=st.data(), value=st.dictionaries(KEYS, JSON, min_size=1, max_size=8))
def test_fuzz_canonical_json_ignores_key_order(data: st.DataObject, value: dict[str, Any]) -> None:
    keys = data.draw(st.permutations(list(value)))
    shuffled = {key: value[key] for key in keys}
    assert canonical_json(shuffled) == canonical_json(value)


@pytest.mark.phase(9)
@FUZZ
@given(name=st.text(max_size=100))
def test_fuzz_tool_name_parsing_only_raises_value_error(name: str) -> None:
    try:
        upstream_id, tool = split_tool_name(name)
    except ValueError:
        return
    assert upstream_id and tool
    assert f"{upstream_id}__{tool}" == name


@pytest.mark.phase(9)
@FUZZ
@given(
    upstream_id=st.from_regex(r"[a-z][a-z0-9]{1,10}", fullmatch=True),
    tool=st.from_regex(r"[a-zA-Z0-9-][a-zA-Z0-9_-]{0,20}", fullmatch=True),
)
def test_fuzz_tool_name_round_trips(upstream_id: str, tool: str) -> None:
    name = make_tool_name(upstream_id, tool)
    assert split_tool_name(name) == (upstream_id, tool)
