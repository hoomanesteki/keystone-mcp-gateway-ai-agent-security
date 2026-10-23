"""What the audit log keeps of a call's arguments (KS-502)."""

import copy
import hashlib
from typing import Any

import pytest

from keystone.audit.redact import (
    MAX_REDACTED_BYTES,
    RedactionConfig,
    args_digest,
    audit_arguments,
    luhn_valid,
    redact,
    redact_string,
)
from keystone.core.canonical import canonical_json

CARD = "4111 1111 1111 1111"
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\nabc123\n-----END RSA PRIVATE KEY-----"


@pytest.mark.phase(5)
def test_redacts_keys_and_patterns() -> None:
    arguments: dict[str, Any] = {
        "api_key": "sk-live-1234",
        "Authorization": "Bearer abcdef0123456789",
        "client_secret": {"deep": ["x"]},
        "db_password": 12345,
        "nested": {"ok": "fine", "access-token": "t"},
        "items": [{"X-Api-Key": "k"}, "plain"],
        "note": f"charge {CARD} today",
        "who": "ssn 123-45-6789, thanks",
        "header": "curl -H 'Authorization: Bearer eyJhbGciOi.payload.sig'",
        "aws": "key AKIAIOSFODNN7EXAMPLE here",
        "pem": f"before {PEM} after",
        "internal": "customer-77",
        "count": 7,
        "ratio": 0.5,
        "flag": True,
        "nothing": None,
    }

    shown = redact(arguments, RedactionConfig.of(["Internal"]))

    assert shown == {
        "api_key": "[redacted]",
        "Authorization": "[redacted]",
        "client_secret": "[redacted]",
        "db_password": "[redacted]",
        "nested": {"ok": "fine", "access-token": "[redacted]"},
        "items": [{"X-Api-Key": "[redacted]"}, "plain"],
        "note": "charge [redacted:card] today",
        "who": "ssn [redacted:ssn], thanks",
        "header": "curl -H 'Authorization: Bearer [redacted]'",
        "aws": "key [redacted:aws-key-id] here",
        "pem": "before [redacted:private-key] after",
        "internal": "[redacted]",
        "count": 7,
        "ratio": 0.5,
        "flag": True,
        "nothing": None,
    }


@pytest.mark.phase(5)
def test_redact_leaves_the_original_alone() -> None:
    arguments = {"password": "p", "nested": {"note": CARD}, "list": [CARD]}
    before = copy.deepcopy(arguments)

    redact(arguments)

    assert arguments == before


@pytest.mark.phase(5)
@pytest.mark.parametrize(
    "number",
    [
        "4111111111111111",
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "5500 0000 0000 0004",
        "378282246310005",  # 15 digits
        "4222222222222",  # 13 digits
        "6011000990139424",
    ],
)
def test_a_card_number_that_passes_luhn_is_masked(number: str) -> None:
    assert redact_string(f"pay with {number}, thanks") == "pay with [redacted:card], thanks"


@pytest.mark.phase(5)
@pytest.mark.parametrize(
    "text",
    [
        "4111111111111112",  # fails Luhn
        "411111111111",  # 12 digits
        "41111111111111111111",  # 20 digits: a longer number, not a card
        "order 1234 5678 9012 shipped",
        "1234-5678-9012",
        "version 2026.10.23.1",
    ],
)
def test_digits_that_are_not_a_card_number_stay(text: str) -> None:
    assert redact_string(text) == text


@pytest.mark.phase(5)
def test_luhn() -> None:
    assert luhn_valid("4111111111111111") and luhn_valid("378282246310005")
    assert not luhn_valid("4111111111111112")


@pytest.mark.phase(5)
@pytest.mark.parametrize("text", ["123-45-6789", "000-12-3456", "(123-45-6789)"])
def test_a_social_security_number_is_masked(text: str) -> None:
    assert "[redacted:ssn]" in redact_string(text) and "-45-6789" not in redact_string(text)


@pytest.mark.phase(5)
@pytest.mark.parametrize(
    "text", ["123-45-678", "12-345-6789", "123-45-67890", "1234-56-7890", "123456789"]
)
def test_digits_that_are_not_a_social_security_number_stay(text: str) -> None:
    assert redact_string(text) == text


@pytest.mark.phase(5)
@pytest.mark.parametrize(
    "text",
    [
        "Bearer abcdefgh12345678",
        "bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
        "Authorization: Bearer a1b2c3d4e5f6",
    ],
)
def test_a_bearer_token_is_masked(text: str) -> None:
    masked = redact_string(text)

    assert "Bearer [redacted]" in masked.replace("bearer", "Bearer")
    assert not any(part in masked for part in ("abcdefgh", "eyJhbG", "a1b2c3"))


@pytest.mark.phase(5)
@pytest.mark.parametrize("text", ["Bearer", "Bearer short", "the bearer of this letter", "Bearers"])
def test_text_that_is_not_a_bearer_token_stays(text: str) -> None:
    assert redact_string(text) == text


@pytest.mark.phase(5)
@pytest.mark.parametrize("key", ["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"])
def test_an_aws_access_key_id_is_masked(key: str) -> None:
    assert redact_string(f"id={key};") == "id=[redacted:aws-key-id];"


@pytest.mark.phase(5)
@pytest.mark.parametrize(
    "text", ["AKIAIOSFODNN7EXAMPL", "akiaiosfodnn7example", "XAKIAIOSFODNN7EXAMPLE", "AKIA"]
)
def test_text_that_is_not_an_aws_key_id_stays(text: str) -> None:
    assert redact_string(text) == text


@pytest.mark.phase(5)
@pytest.mark.parametrize(
    "header", ["RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY"]
)
def test_a_private_key_block_is_masked(header: str) -> None:
    block = f"-----BEGIN {header}-----\nMIIEvQIBADANBg\n-----END {header}-----"

    assert redact_string(f"key: {block}\nnext line") == "key: [redacted:private-key]\nnext line"
    # A block cut off before its footer is masked to the end, so nothing of the key is kept.
    assert redact_string(f"-----BEGIN {header}-----\nMIIEvQIBADANBg") == "[redacted:private-key]"


@pytest.mark.phase(5)
def test_a_public_key_is_not_a_secret() -> None:
    public = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZI\n-----END PUBLIC KEY-----"

    assert redact_string(public) == public


@pytest.mark.phase(5)
def test_only_the_listed_key_is_masked_and_not_one_that_contains_it() -> None:
    config = RedactionConfig.of(["ssn"])

    shown = redact({"SSN": "x", "ssn_checked": "yes", "passport": "p"}, config)

    assert shown == {"SSN": "[redacted]", "ssn_checked": "yes", "passport": "p"}


@pytest.mark.phase(5)
def test_truncates_long_values() -> None:
    long = "x" * 3000
    whole = hashlib.sha256(long.encode()).hexdigest()

    cut = redact_string(long)

    assert cut == "x" * 256 + f"...[sha256:{whole}]"
    # The limit is 2,048 characters: up to it the string is kept, one over it is cut.
    assert redact_string("y" * 2048) == "y" * 2048
    assert redact_string("y" * 2049).startswith("y" * 256 + "...[sha256:")
    assert len(redact_string("y" * 2049)) == 256 + len("...[sha256:") + 64 + 1


@pytest.mark.phase(5)
def test_a_card_number_across_the_cut_is_masked_not_half_kept() -> None:
    text = "a" * 250 + " " + CARD + " " + "b" * 3000

    cut = redact_string(text)

    assert "4111" not in cut and "1111" not in cut
    assert cut.startswith("a" * 250 + " [reda")  # the mask was cut, the digits were not kept


@pytest.mark.phase(5)
def test_the_hash_of_a_long_string_is_of_the_original_not_the_masked_text() -> None:
    text = CARD + " " + "z" * 3000

    cut = redact_string(text)

    assert cut.endswith(f"[sha256:{hashlib.sha256(text.encode()).hexdigest()}]")
    assert CARD not in cut


@pytest.mark.phase(5)
def test_digest_of_original_args() -> None:
    arguments = {"to": "x@acme.test", "api_key": "sk-secret-1", "card": CARD, "n": 1}

    digest = args_digest(arguments)

    assert digest == hashlib.sha256(canonical_json(arguments)).hexdigest()
    # The digest of the redacted form is a different one: the log proves the original, not the mask.
    assert digest != args_digest(redact(arguments))
    # The order of the keys is not part of it, and redacting leaves it as it was.
    assert digest == args_digest(dict(reversed(list(arguments.items()))))
    shown, stored = audit_arguments(arguments)
    assert stored == digest
    assert shown["api_key"] == "[redacted]" and shown["card"] == "[redacted:card]"
    assert "sk-secret-1" not in str(shown) and CARD not in str(shown)


@pytest.mark.phase(5)
def test_arguments_that_are_not_json_have_no_digest_and_still_get_a_record() -> None:
    arguments = {"x": float("nan")}

    assert args_digest(arguments) is None
    shown, digest = audit_arguments(arguments)
    assert digest is None and shown == {"x": "nan"}


@pytest.mark.phase(5)
def test_what_is_stored_is_in_the_form_jsonb_returns() -> None:
    shown, _ = audit_arguments({"big": 1e22, "zero": -0.0, "text": "a\x00b"})

    assert shown == {"big": 10**22, "zero": 0.0, "text": "a\\u0000b"}


@pytest.mark.phase(5)
def test_a_record_cannot_grow_with_its_arguments() -> None:
    arguments = {f"key{i}": "v" * 200 for i in range(500)}  # about 100 KB
    assert len(canonical_json(arguments)) > MAX_REDACTED_BYTES

    shown, digest = audit_arguments(arguments)

    assert list(shown) == ["[truncated]"] and "bytes after redaction" in shown["[truncated]"]
    assert digest == hashlib.sha256(canonical_json(arguments)).hexdigest()


@pytest.mark.phase(5)
def test_nesting_that_is_too_deep_is_cut() -> None:
    deep: Any = "leaf"
    for _ in range(200):
        deep = {"k": deep}

    shown, digest = audit_arguments({"start": deep})

    assert "[truncated]" in str(shown)
    assert digest is None or len(digest) == 64
