"""KS-305: credentials are encrypted at rest, looked up by mode, and re-encrypted on rotation."""

import base64
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr

from keystone.core.errors import Code, Reject
from keystone.identity.vault import (
    PUBLISHED_KEY_IDS,
    Cipher,
    UnknownUpstream,
    Vault,
    VaultError,
    check_headers,
    key_id,
)
from keystone.logging import SECRETS
from tests.fixtures.vault import MemoryCredentialStore

ROOT = Path(__file__).resolve().parents[2]
MODES = {
    "mail": ("acme", "static"),
    "crm": ("acme", "per_user"),
    "echo": ("acme", "none"),
    "notes": ("globex", "static"),
}
KEY = "mail-api-key-4d1e0b7a9c"


def fresh_key() -> str:
    return Fernet.generate_key().decode()


def vault_with(keys: str) -> tuple[Vault, MemoryCredentialStore]:
    store = MemoryCredentialStore(dict(MODES))
    return Vault(Cipher(keys), store), store


@pytest.fixture(autouse=True)
def empty_registry() -> Iterator[None]:
    SECRETS.clear()
    yield
    SECRETS.clear()


@pytest.mark.phase(3)
async def test_encrypt_decrypt_roundtrip() -> None:
    vault, store = vault_with(fresh_key())
    await vault.set("acme", "mail", {"X-Api-Key": KEY})

    headers = await vault.headers_for("acme", "mail", "alice")

    assert list(headers) == ["X-Api-Key"]
    assert isinstance(headers["X-Api-Key"], SecretStr)
    assert headers["X-Api-Key"].get_secret_value() == KEY
    assert KEY not in repr(headers) and KEY not in str(headers)
    [stored] = store.ciphertexts()
    assert KEY.encode() not in stored
    assert base64.urlsafe_b64encode(KEY.encode()) not in stored


@pytest.mark.phase(3)
async def test_rotation_reencrypts() -> None:
    old, new = fresh_key(), fresh_key()
    vault, store = vault_with(old)
    await vault.set("acme", "mail", {"X-Api-Key": KEY})
    await vault.set("acme", "crm", {"Authorization": "Bearer alice-token-0123456"}, "alice")
    before = store.ciphertexts()

    # A new key goes first and the old one stays, so everything still decrypts.
    rotating = Vault(Cipher(f"{new},{old}"), store)
    during = await rotating.headers_for("acme", "mail", "alice")
    assert during["X-Api-Key"].get_secret_value() == KEY
    report = await rotating.rotate_keys()
    assert (report.rotated, report.unchanged, report.failed) == (2, 0, [])
    assert store.ciphertexts() != before
    assert {info.key_id for info in await store.infos()} == {key_id(new)}

    # The old key can go: nothing is left that needs it.
    only_new = Vault(Cipher(new), store)
    after = await only_new.headers_for("acme", "mail", "alice")
    assert after["X-Api-Key"].get_secret_value() == KEY
    with pytest.raises(VaultError, match="cannot be decrypted"):
        await Vault(Cipher(old), store).headers_for("acme", "mail", "alice")

    again = await only_new.rotate_keys()
    assert (again.rotated, again.unchanged) == (0, 2)


@pytest.mark.phase(3)
async def test_rotation_reports_a_row_no_key_opens_and_goes_on() -> None:
    first, stranger = fresh_key(), fresh_key()
    vault, store = vault_with(first)
    await vault.set("acme", "mail", {"X-Api-Key": KEY})
    elsewhere = Vault(Cipher(stranger), store)
    await elsewhere.set("acme", "crm", {"X-Api-Key": "other-key-123456789"}, "bob")

    report = await Vault(Cipher(f"{fresh_key()},{first}"), store).rotate_keys()

    assert report.rotated == 1
    assert len(report.failed) == 1


@pytest.mark.phase(3)
async def test_each_mode_sends_what_it_should() -> None:
    vault, _ = vault_with(fresh_key())
    await vault.set("acme", "mail", {"X-Api-Key": KEY})
    await vault.set("acme", "crm", {"X-Api-Key": "alice-crm-key-0123456"}, "alice")
    await vault.set("acme", "echo", {"X-Api-Key": "ignored-key-01234567"})

    async def sent(upstream: str, user: str) -> dict[str, str]:
        found = await vault.headers_for("acme", upstream, user)
        return {name: value.get_secret_value() for name, value in found.items()}

    assert await sent("mail", "alice") == {"X-Api-Key": KEY}
    assert await sent("mail", "bob") == {"X-Api-Key": KEY}  # static: the same for everybody
    assert await sent("crm", "alice") == {"X-Api-Key": "alice-crm-key-0123456"}
    assert await sent("echo", "alice") == {}  # mode none sends nothing, whatever is stored


@pytest.mark.phase(3)
async def test_a_per_user_upstream_without_the_users_credential_refuses_the_call() -> None:
    vault, _ = vault_with(fresh_key())
    await vault.set("acme", "crm", {"X-Api-Key": "alice-crm-key-0123456"}, "alice")

    with pytest.raises(Reject) as raised:
        await vault.headers_for("acme", "crm", "bob")

    assert raised.value.code is Code.DENIED
    assert raised.value.message == "no credential for this user on crm"


@pytest.mark.phase(3)
async def test_a_static_upstream_without_a_credential_sends_nothing() -> None:
    vault, _ = vault_with(fresh_key())

    assert await vault.headers_for("acme", "mail", "alice") == {}


@pytest.mark.phase(3)
async def test_the_service_credential_is_the_static_one() -> None:
    vault, _ = vault_with(fresh_key())
    await vault.set("acme", "mail", {"X-Api-Key": KEY})
    await vault.set("acme", "crm", {"X-Api-Key": "alice-crm-key-0123456"}, "alice")
    await vault.set("acme", "echo", {"X-Api-Key": "ignored-key-01234567"})

    mail = await vault.service_headers("acme", "mail")
    crm = await vault.service_headers("acme", "crm")
    echo = await vault.service_headers("acme", "echo")
    nowhere = await vault.service_headers("acme", "nowhere")

    assert mail["X-Api-Key"].get_secret_value() == KEY
    assert (crm, echo, nowhere) == ({}, {}, {})  # a user's credential is never used for syncing


@pytest.mark.phase(3)
async def test_a_tenant_cannot_reach_another_tenants_upstream() -> None:
    vault, _ = vault_with(fresh_key())

    with pytest.raises(UnknownUpstream):
        await vault.set("acme", "notes", {"X-Api-Key": KEY})
    with pytest.raises(UnknownUpstream):
        await vault.headers_for("acme", "notes", "alice")


@pytest.mark.phase(3)
async def test_setting_a_credential_again_replaces_it() -> None:
    vault, store = vault_with(fresh_key())
    await vault.set("acme", "mail", {"X-Api-Key": KEY})
    await vault.set("acme", "mail", {"X-Api-Key": "second-key-0123456789"})

    found = await vault.headers_for("acme", "mail", "alice")

    assert found["X-Api-Key"].get_secret_value() == "second-key-0123456789"
    assert len(store.ciphertexts()) == 1


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    ("headers", "problem"),
    [
        ({}, "at least one header"),
        ({"Bad Name": "value-0123456"}, "usable header name"),
        ({"X-Key\r\nX-Evil": "v"}, "usable header name"),
        ({"Host": "evil.test"}, "set by the HTTP layer"),
        ({"content-length": "0"}, "set by the HTTP layer"),
        ({"Mcp-Session-Id": "abc"}, "set by the HTTP layer"),
        ({"X-Api-Key": ""}, "1 to 4096 characters"),
        ({"X-Api-Key": "x" * 4097}, "1 to 4096 characters"),
        ({"X-Api-Key": "line one\nline two"}, "printable ASCII on one line"),
        ({"X-Api-Key": "café-key-0123"}, "printable ASCII on one line"),
        ({"X-Api-Key": "a-value-0123", "x-api-key": "b-value-0123"}, "given twice"),
    ],
)
def test_headers_that_cannot_be_sent_are_refused(headers: dict[str, str], problem: str) -> None:
    with pytest.raises(ValueError, match=problem):
        check_headers(headers)


@pytest.mark.phase(3)
def test_authorization_and_ordinary_names_are_allowed() -> None:
    assert check_headers({"Authorization": "Bearer abc.def", "X-Api-Key": "k-0123456789"})


@pytest.mark.phase(3)
def test_the_first_master_key_encrypts_and_every_one_decrypts() -> None:
    first, second = fresh_key(), fresh_key()
    cipher = Cipher(f" {first} , {second} ")

    token, kid = cipher.encrypt({"X-Api-Key": KEY})

    assert kid == key_id(first) == cipher.primary_id
    assert Fernet(first.encode()).decrypt(token)
    with pytest.raises(InvalidToken):
        Fernet(second.encode()).decrypt(token)
    older, _ = Cipher(second).encrypt({"X-Api-Key": KEY})
    assert cipher.decrypt(older) == {"X-Api-Key": KEY}


@pytest.mark.phase(3)
@pytest.mark.parametrize("bad", ["", " ", ",", "not-a-key", "short=", "x" * 44])
def test_a_master_key_setting_that_cannot_work_is_refused_without_echoing_it(bad: str) -> None:
    with pytest.raises(VaultError) as raised:
        Cipher(bad)

    echoed = bad.strip(", ")
    assert not echoed or echoed not in str(raised.value)


@pytest.mark.phase(3)
def test_a_bad_entry_after_a_good_one_is_found_and_not_echoed() -> None:
    secret_looking = "this-is-not-a-fernet-key-but-looks-private"

    with pytest.raises(VaultError, match="entry 2") as raised:
        Cipher(f"{fresh_key()},{secret_looking}")

    assert secret_looking not in str(raised.value)


@pytest.mark.phase(3)
def test_the_key_published_in_env_example_is_refused_in_prod_and_nowhere_else() -> None:
    published = next(
        line.partition("=")[2]
        for line in (ROOT / ".env.example").read_text().splitlines()
        if line.startswith("KEYSTONE_MASTER_KEYS=")
    )

    assert key_id(published) in PUBLISHED_KEY_IDS
    Cipher(published)  # fine on a developer's machine
    with pytest.raises(VaultError, match="published"):
        Cipher(published, refuse_published=True)
    Cipher(fresh_key(), refuse_published=True)


@pytest.mark.phase(3)
async def test_decrypting_registers_the_secret_with_the_log_scrubber() -> None:
    vault, _ = vault_with(fresh_key())
    short = "tiny"
    await vault.set("acme", "mail", {"X-Api-Key": KEY, "X-Org": short})
    SECRETS.clear()  # as if the process had just started

    await vault.headers_for("acme", "mail", "alice")

    redacted = SECRETS.redact(f"calling with {KEY} and {short}")
    assert redacted == f"calling with [redacted] and {short}"


@pytest.mark.phase(3)
async def test_setting_a_credential_registers_it_too() -> None:
    vault, _ = vault_with(fresh_key())

    await vault.set("acme", "mail", {"X-Api-Key": KEY})

    assert SECRETS.redact(KEY) == "[redacted]"


@pytest.mark.phase(3)
def test_a_ciphertext_nobody_wrote_is_a_vault_error() -> None:
    key = Fernet.generate_key()
    cipher = Cipher(key.decode())
    encrypted_elsewhere = Fernet(Fernet.generate_key()).encrypt(b'{"a":"b"}')
    not_json = Fernet(key).encrypt(b"not json")
    not_an_object = Fernet(key).encrypt(b'["a"]')
    not_strings = Fernet(key).encrypt(b'{"a": 1}')

    with pytest.raises(VaultError, match="cannot be decrypted"):
        cipher.decrypt(encrypted_elsewhere)
    with pytest.raises(VaultError, match="cannot be decrypted"):
        cipher.decrypt(b"not a token")
    for token in (not_json, not_an_object, not_strings):
        with pytest.raises(VaultError, match="not what the vault wrote"):
            cipher.decrypt(token)


@pytest.mark.phase(6)
def test_a_json_value_round_trips_and_is_not_readable_in_the_ciphertext() -> None:
    cipher = Cipher(fresh_key())
    arguments = {"from_account": "CHK-001", "amount": 900.5, "nested": {"to": ["SAV-002", None]}}

    sealed = cipher.encrypt_json(arguments)

    assert cipher.decrypt_json(sealed) == arguments
    assert b"CHK-001" not in sealed and b"900.5" not in sealed
    # Nothing here is a credential, so the log scrubber learns none of it.
    assert SECRETS.redact("CHK-001 900.5") == "CHK-001 900.5"


@pytest.mark.phase(6)
def test_a_json_value_opens_with_any_master_key_and_with_no_other() -> None:
    old, new = fresh_key(), fresh_key()
    sealed = Cipher(old).encrypt_json({"amount": 900})

    assert Cipher(f"{new},{old}").decrypt_json(sealed) == {"amount": 900}
    with pytest.raises(VaultError, match="cannot be decrypted"):
        Cipher(new).decrypt_json(sealed)
    with pytest.raises(VaultError, match="cannot be decrypted"):
        Cipher(old).decrypt_json(b"not a token")


@pytest.mark.phase(6)
def test_the_vault_hands_out_its_cipher() -> None:
    vault, _ = vault_with(fresh_key())

    assert vault.cipher.decrypt_json(vault.cipher.encrypt_json([1, 2])) == [1, 2]
