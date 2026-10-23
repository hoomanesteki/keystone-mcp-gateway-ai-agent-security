"""KS-306: credentials taken from the environment, and an app that cannot start without a vault."""

from typing import Any

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from keystone.app import create_app
from keystone.identity.vault import Cipher, Vault, VaultError
from keystone.registry.config import (
    ConfigError,
    UpstreamConfig,
    apply_config_upstreams,
    seed_credentials,
)
from keystone.settings import Settings
from tests.fixtures.vault import MemoryCredentialStore

ISSUER = "http://idp.test/realms/keystone"
MODES = {"mail": ("acme", "static"), "crm": ("acme", "per_user"), "files": ("acme", "static")}


def upstream(name: str = "mail", **fields: Any) -> UpstreamConfig:
    return UpstreamConfig(
        id=name,
        tenant="acme",
        url=f"http://{name}.test/mcp",
        credential_mode="static",
        credential_env={"X-Api-Key": f"{name.upper()}_API_KEY"},
        **fields,
    )


@pytest.mark.phase(3)
def test_credential_env_names_a_header_and_a_variable() -> None:
    config = upstream()

    assert config.credential_env == {"X-Api-Key": "MAIL_API_KEY"}


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    ("env", "problem"),
    [
        ({"Bad Header": "MAIL_API_KEY"}, "usable header name"),
        ({"X-Api-Key": "not a name"}, "environment variable name"),
        ({"X-Api-Key": "KEYSTONE_MASTER_KEYS"}, "Keystone's own setting"),
        ({"X-Api-Key": "keystone_database_url"}, "Keystone's own setting"),
    ],
)
def test_credential_env_refuses_what_cannot_be_a_credential(
    env: dict[str, str], problem: str
) -> None:
    with pytest.raises(ValidationError, match=problem):
        UpstreamConfig(id="mail", tenant="acme", url="http://mail.test/mcp", credential_env=env)


@pytest.mark.phase(3)
async def test_credential_env_on_an_upstream_that_never_sends_one_is_a_config_error() -> None:
    never_sent = UpstreamConfig(
        id="mail",
        tenant="acme",
        url="http://127.0.0.1:1/mcp",
        credential_env={"X-Api-Key": "MAIL_API_KEY"},
    )
    on_stdio = UpstreamConfig(
        id="tools",
        tenant="acme",
        transport="stdio",
        command=["python"],
        credential_mode="static",
        credential_env={"X-Api-Key": "TOOLS_API_KEY"},
    )

    with pytest.raises(ConfigError) as raised:
        await apply_config_upstreams(None, [never_sent, on_stdio], ["acme"], allow_private=True)  # type: ignore[arg-type]

    assert "credential_mode none" in str(raised.value)
    assert "not http" in str(raised.value)


def vault() -> tuple[Vault, MemoryCredentialStore]:
    store = MemoryCredentialStore(dict(MODES))
    return Vault(Cipher(Fernet.generate_key().decode()), store), store


@pytest.mark.phase(3)
async def test_seeding_stores_what_the_environment_holds_and_only_when_it_changed() -> None:
    seeded_vault, store = vault()
    configs = [upstream("mail"), upstream("files")]
    environ = {"MAIL_API_KEY": "mail-key-0123456789", "FILES_API_KEY": "files-key-012345678"}

    first = await seed_credentials(seeded_vault, configs, environ)
    before = store.ciphertexts()
    again = await seed_credentials(seeded_vault, configs, environ)
    changed = await seed_credentials(
        seeded_vault, configs, {**environ, "MAIL_API_KEY": "new-key-0123456789"}
    )

    assert first == ["mail", "files"]
    assert again == []  # nothing changed, so nothing was rewritten
    assert store.ciphertexts()[1:] == before[1:]
    assert changed == ["mail"]
    found = await seeded_vault.headers_for("acme", "mail", "alice")
    assert found["X-Api-Key"].get_secret_value() == "new-key-0123456789"


@pytest.mark.phase(3)
async def test_a_variable_that_is_not_set_leaves_the_stored_credential_alone() -> None:
    seeded_vault, store = vault()
    await seed_credentials(
        seeded_vault, [upstream("mail")], {"MAIL_API_KEY": "mail-key-0123456789"}
    )
    before = store.ciphertexts()

    written = await seed_credentials(seeded_vault, [upstream("mail")], {})
    empty = await seed_credentials(seeded_vault, [upstream("mail")], {"MAIL_API_KEY": ""})

    assert written == empty == []
    assert store.ciphertexts() == before


@pytest.mark.phase(3)
async def test_an_upstream_without_credential_env_is_skipped() -> None:
    seeded_vault, store = vault()
    plain = UpstreamConfig(id="mail", tenant="acme", url="http://mail.test/mcp")

    assert (
        await seed_credentials(seeded_vault, [plain], {"MAIL_API_KEY": "mail-key-0123456789"}) == []
    )
    assert store.ciphertexts() == []


@pytest.mark.phase(3)
def test_an_app_whose_upstreams_use_credentials_is_not_built_without_master_keys() -> None:
    settings = Settings(
        env="test", oidc_issuer=ISSUER, upstreams=[upstream("mail"), upstream("files")]
    )

    with pytest.raises(VaultError, match=r"mail, files .*KEYSTONE_MASTER_KEYS must be set"):
        create_app(settings)


@pytest.mark.phase(3)
def test_an_app_with_a_master_key_that_cannot_work_is_not_built_and_does_not_print_it() -> None:
    settings = Settings(
        env="test",
        oidc_issuer=ISSUER,
        master_keys="this-is-not-a-fernet-key-but-looks-private",  # type: ignore[arg-type]
    )

    with pytest.raises(VaultError) as raised:
        create_app(settings)

    assert "this-is-not-a-fernet-key" not in str(raised.value)


@pytest.mark.phase(3)
def test_an_app_without_credentials_in_its_config_needs_no_master_key() -> None:
    plain = UpstreamConfig(id="mail", tenant="acme", url="http://mail.test/mcp")

    app = create_app(Settings(env="test", oidc_issuer=ISSUER, upstreams=[plain]))

    assert app.state.vault is None
