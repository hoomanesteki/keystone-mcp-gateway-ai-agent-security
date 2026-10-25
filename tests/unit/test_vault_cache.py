"""KS-992: the vault keeps an opened credential for a while, and a change made here drops it."""

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from keystone.core.errors import Reject
from keystone.identity.vault import Cipher, Lookup, Vault
from tests.fixtures.vault import MemoryCredentialStore

pytestmark = pytest.mark.phase(9)

MODES = {"mail": ("acme", "static"), "crm": ("acme", "per_user")}


class CountingStore(MemoryCredentialStore):
    def __init__(self) -> None:
        super().__init__(dict(MODES))
        self.lookups = 0

    async def lookup(self, tenant_id: str, upstream_id: str, user_id: str | None) -> Lookup | None:
        self.lookups += 1
        return await super().lookup(tenant_id, upstream_id, user_id)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make(ttl: float = 60.0) -> tuple[Vault, CountingStore, Clock]:
    store, clock = CountingStore(), Clock()
    vault = Vault(Cipher(Fernet.generate_key().decode()), store, cache_ttl_s=ttl, clock=clock)
    return vault, store, clock


def secret(headers: dict[str, SecretStr]) -> str:
    return headers["X-Api-Key"].get_secret_value()


async def test_a_second_call_does_not_read_or_decrypt_again() -> None:
    vault, store, _ = make()
    await vault.set("acme", "mail", {"X-Api-Key": "one"})
    store.lookups = 0

    first = await vault.headers_for("acme", "mail", "alice")
    second = await vault.headers_for("acme", "mail", "alice")

    assert secret(first) == secret(second) == "one"
    assert store.lookups == 1
    # Each call gets a dict of its own, so one call cannot change what the next one sends.
    first.clear()
    assert secret(await vault.headers_for("acme", "mail", "alice")) == "one"


async def test_the_entry_expires_after_the_time_limit() -> None:
    vault, store, clock = make(ttl=60)
    await vault.set("acme", "mail", {"X-Api-Key": "one"})
    store.lookups = 0
    await vault.headers_for("acme", "mail", "alice")

    clock.now += 59
    await vault.headers_for("acme", "mail", "alice")
    assert store.lookups == 1
    clock.now += 2
    await vault.headers_for("acme", "mail", "alice")
    assert store.lookups == 2


async def test_a_change_made_by_another_process_is_seen_when_the_entry_expires() -> None:
    vault, store, clock = make(ttl=60)
    await vault.set("acme", "mail", {"X-Api-Key": "one"})
    await vault.headers_for("acme", "mail", "alice")
    # What the CLI does: it writes the row through a vault of its own.
    await Vault(vault.cipher, store).set("acme", "mail", {"X-Api-Key": "two"})

    assert secret(await vault.headers_for("acme", "mail", "alice")) == "one"
    clock.now += 61
    assert secret(await vault.headers_for("acme", "mail", "alice")) == "two"


async def test_set_here_takes_effect_at_once() -> None:
    vault, _, _ = make()
    await vault.set("acme", "mail", {"X-Api-Key": "one"})
    await vault.headers_for("acme", "mail", "alice")

    await vault.set("acme", "mail", {"X-Api-Key": "two"})

    assert secret(await vault.headers_for("acme", "mail", "alice")) == "two"


async def test_rotating_the_keys_drops_what_was_kept() -> None:
    vault, store, _ = make()
    await vault.set("acme", "mail", {"X-Api-Key": "one"})
    await vault.headers_for("acme", "mail", "alice")
    store.lookups = 0

    await vault.rotate_keys()
    await vault.headers_for("acme", "mail", "alice")

    assert store.lookups == 1


async def test_users_do_not_share_an_entry_and_a_refusal_is_not_kept() -> None:
    vault, store, _ = make()
    await vault.set("acme", "crm", {"X-Api-Key": "alice-key"}, user_id="alice")

    with pytest.raises(Reject):
        await vault.headers_for("acme", "crm", "bob")
    assert secret(await vault.headers_for("acme", "crm", "alice")) == "alice-key"
    await vault.set("acme", "crm", {"X-Api-Key": "bob-key"}, user_id="bob")
    assert secret(await vault.headers_for("acme", "crm", "bob")) == "bob-key"
    assert secret(await vault.headers_for("acme", "crm", "alice")) == "alice-key"
    assert store.lookups >= 4


async def test_a_limit_of_zero_keeps_nothing() -> None:
    vault, store, _ = make(ttl=0)
    await vault.set("acme", "mail", {"X-Api-Key": "one"})
    store.lookups = 0

    await vault.headers_for("acme", "mail", "alice")
    await vault.headers_for("acme", "mail", "alice")

    assert store.lookups == 2
