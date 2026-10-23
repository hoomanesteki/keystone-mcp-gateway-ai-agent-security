"""KS-305: the vault on Postgres, and the `keystone cred` commands."""

import json
from collections.abc import Iterator

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.errors import Code, Reject
from keystone.db.tenants import upsert_tenants
from keystone.identity.credential_repo import CredentialRepo
from keystone.identity.vault import Cipher, UnknownUpstream, Vault, key_id
from keystone.logging import SECRETS
from keystone.registry.repo import UpstreamRepo, UpstreamSpec
from keystone.settings import TenantConfig
from tests.fixtures.cli import invoke

pytestmark = [pytest.mark.phase(3), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]
MASTER = Fernet.generate_key().decode()
API_KEY = "mail-api-key-4d1e0b7a9c"


@pytest.fixture(autouse=True)
def empty_registry() -> Iterator[None]:
    SECRETS.clear()
    yield
    SECRETS.clear()


async def register(sessions: Sessions) -> None:
    await upsert_tenants(
        sessions,
        [TenantConfig(id="acme", name="Acme Corp"), TenantConfig(id="globex", name="Globex")],
    )
    upstreams = UpstreamRepo(sessions)
    for upstream_id, tenant, mode in (
        ("mail", "acme", "static"),
        ("crm", "acme", "per_user"),
        ("echo", "acme", "none"),
        ("notes", "globex", "static"),
    ):
        await upstreams.upsert(
            UpstreamSpec(
                id=upstream_id,
                tenant_id=tenant,
                url=f"http://{upstream_id}.test/mcp",
                credential_mode=mode,  # type: ignore[arg-type]
            )
        )


def vault_on(sessions: Sessions, keys: str = MASTER) -> Vault:
    return Vault(Cipher(keys), CredentialRepo(sessions))


async def rows(sessions: Sessions) -> list[tuple[str, str | None, bytes, str]]:
    async with sessions() as session:
        found = await session.execute(
            text(
                "SELECT upstream_id, user_id, ciphertext, key_id FROM credentials "
                "ORDER BY upstream_id, user_id NULLS FIRST"
            )
        )
        return [(a, b, bytes(c), d) for a, b, c, d in found]


@pytest.mark.phase(3)
async def test_static_and_per_user_lookup(sessionmaker: Sessions) -> None:
    await register(sessionmaker)
    vault = vault_on(sessionmaker)
    await vault.set("acme", "mail", {"X-Api-Key": API_KEY})
    await vault.set("acme", "crm", {"X-Api-Key": "alice-crm-key-0123456"}, "alice")
    await vault.set("acme", "crm", {"X-Api-Key": "bob-crm-key-012345678"}, "bob")
    await vault.set("globex", "notes", {"X-Api-Key": "globex-notes-key-0123"})

    async def sent(tenant: str, upstream: str, user: str) -> dict[str, str]:
        found = await vault.headers_for(tenant, upstream, user)
        return {name: value.get_secret_value() for name, value in found.items()}

    assert await sent("acme", "mail", "alice") == {"X-Api-Key": API_KEY}
    assert await sent("acme", "mail", "bob") == {"X-Api-Key": API_KEY}
    assert await sent("acme", "crm", "alice") == {"X-Api-Key": "alice-crm-key-0123456"}
    assert await sent("acme", "crm", "bob") == {"X-Api-Key": "bob-crm-key-012345678"}
    assert await sent("acme", "echo", "alice") == {}
    assert await sent("globex", "notes", "bob") == {"X-Api-Key": "globex-notes-key-0123"}
    assert {
        name: v.get_secret_value()
        for name, v in (await vault.service_headers("acme", "mail")).items()
    } == {"X-Api-Key": API_KEY}
    assert await vault.service_headers("acme", "crm") == {}


@pytest.mark.phase(3)
async def test_missing_per_user_credential_denied(sessionmaker: Sessions) -> None:
    await register(sessionmaker)
    vault = vault_on(sessionmaker)
    await vault.set("acme", "crm", {"X-Api-Key": "alice-crm-key-0123456"}, "alice")

    with pytest.raises(Reject) as raised:
        await vault.headers_for("acme", "crm", "bob")

    assert raised.value.code is Code.DENIED
    assert raised.value.message == "no credential for this user on crm"


@pytest.mark.phase(3)
async def test_the_database_holds_ciphertext_only(sessionmaker: Sessions) -> None:
    await register(sessionmaker)
    await vault_on(sessionmaker).set("acme", "mail", {"X-Api-Key": API_KEY})

    [(upstream, user, ciphertext, stored_key)] = await rows(sessionmaker)

    assert (upstream, user) == ("mail", None)
    assert API_KEY.encode() not in ciphertext
    assert b"X-Api-Key" not in ciphertext  # not even the header name
    assert stored_key == key_id(MASTER)
    async with sessionmaker() as session:
        everything = await session.execute(text("SELECT row_to_json(c)::text FROM credentials c"))
        assert API_KEY not in "".join(everything.scalars())


@pytest.mark.phase(3)
async def test_one_static_credential_per_upstream(sessionmaker: Sessions) -> None:
    await register(sessionmaker)
    vault = vault_on(sessionmaker)
    await vault.set("acme", "mail", {"X-Api-Key": API_KEY})
    await vault.set("acme", "mail", {"X-Api-Key": "second-key-0123456789"})

    assert len(await rows(sessionmaker)) == 1
    # The table itself refuses a second row for the same owner, with a null user included.
    async with sessionmaker() as session, session.begin():
        with pytest.raises(IntegrityError):
            await session.execute(
                text(
                    "INSERT INTO credentials "
                    "(id, tenant_id, upstream_id, user_id, ciphertext, key_id) "
                    "VALUES ('x', 'acme', 'mail', NULL, '\\x00', 'k')"
                )
            )


@pytest.mark.phase(3)
async def test_a_credential_for_an_upstream_that_is_not_registered_is_refused(
    sessionmaker: Sessions,
) -> None:
    await register(sessionmaker)
    vault = vault_on(sessionmaker)

    with pytest.raises(UnknownUpstream):
        await vault.set("acme", "ghost", {"X-Api-Key": API_KEY})
    with pytest.raises(UnknownUpstream):
        await vault.set("globex", "mail", {"X-Api-Key": API_KEY})  # mail belongs to acme
    assert await rows(sessionmaker) == []


@pytest.mark.phase(3)
async def test_cli_set_reads_stdin(sessionmaker: Sessions, test_database_url: str) -> None:
    await register(sessionmaker)

    result = await invoke(
        test_database_url,
        ["cred", "set", "--upstream", "mail", "--header", "X-Api-Key"],
        input="piped-key-0123456789\n",
        KEYSTONE_MASTER_KEYS=MASTER,
    )

    assert result.exit_code == 0, result.output
    assert "stored the credential of mail for all callers" in result.output
    assert "piped-key-0123456789" not in result.output
    found = await vault_on(sessionmaker).headers_for("acme", "mail", "alice")
    assert found["X-Api-Key"].get_secret_value() == "piped-key-0123456789"  # no newline


@pytest.mark.phase(3)
async def test_cli_set_can_read_the_value_from_the_environment_and_set_it_for_one_user(
    sessionmaker: Sessions, test_database_url: str
) -> None:
    await register(sessionmaker)

    result = await invoke(
        test_database_url,
        [
            "cred",
            "set",
            "--upstream",
            "crm",
            "--user",
            "alice",
            "--header",
            "X-Api-Key",
            "--from-env",
            "ALICE_CRM_KEY",
        ],
        KEYSTONE_MASTER_KEYS=MASTER,
        ALICE_CRM_KEY="from-env-key-0123456",
    )

    assert result.exit_code == 0, result.output
    assert "for user alice" in result.output and "from-env-key-0123456" not in result.output
    found = await vault_on(sessionmaker).headers_for("acme", "crm", "alice")
    assert found["X-Api-Key"].get_secret_value() == "from-env-key-0123456"


@pytest.mark.phase(3)
async def test_cli_set_has_no_option_that_takes_the_value_on_the_command_line(
    sessionmaker: Sessions, test_database_url: str
) -> None:
    await register(sessionmaker)

    result = await invoke(
        test_database_url,
        [
            "cred",
            "set",
            "--upstream",
            "mail",
            "--header",
            "X-Api-Key",
            "--value",
            "oops-0123456789",
        ],
        KEYSTONE_MASTER_KEYS=MASTER,
    )

    assert result.exit_code == 2
    assert await rows(sessionmaker) == []


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    ("args", "keys", "stdin", "message"),
    [
        (
            ["--upstream", "ghost", "--header", "X-Api-Key"],
            MASTER,
            "key-0123456789\n",
            "no upstream 'ghost'",
        ),
        (
            ["--upstream", "mail", "--header", "X-Api-Key"],
            "",
            "key-0123456789\n",
            "KEYSTONE_MASTER_KEYS is not set",
        ),
        (
            ["--upstream", "mail", "--header", "X-Api-Key"],
            "nope",
            "key-0123456789\n",
            "not a Fernet key",
        ),
        (["--upstream", "mail", "--header", "X-Api-Key"], MASTER, "\n", "the value is empty"),
        (
            ["--upstream", "mail", "--header", "Host"],
            MASTER,
            "key-0123456789\n",
            "set by the HTTP layer",
        ),
        (
            ["--upstream", "mail", "--header", "X-Api-Key", "--from-env", "NOT_SET_ANYWHERE"],
            MASTER,
            "",
            "NOT_SET_ANYWHERE is not set",
        ),
    ],
)
async def test_cli_set_explains_what_is_wrong_and_stores_nothing(
    sessionmaker: Sessions,
    test_database_url: str,
    args: list[str],
    keys: str,
    stdin: str,
    message: str,
) -> None:
    await register(sessionmaker)

    result = await invoke(
        test_database_url,
        ["cred", "set", *args],
        input=stdin,
        KEYSTONE_MASTER_KEYS=keys,
    )

    assert result.exit_code == 1, result.output
    assert message in result.output
    assert "key-0123456789" not in result.output
    assert await rows(sessionmaker) == []


@pytest.mark.phase(3)
async def test_cli_set_warns_when_the_credential_would_not_be_sent(
    sessionmaker: Sessions, test_database_url: str
) -> None:
    await register(sessionmaker)

    none_mode = await invoke(
        test_database_url,
        ["cred", "set", "--upstream", "echo", "--header", "X-Api-Key"],
        input="key-0123456789\n",
        KEYSTONE_MASTER_KEYS=MASTER,
    )

    assert none_mode.exit_code == 0
    assert "credential_mode none" in none_mode.output


@pytest.mark.phase(3)
async def test_cred_list_shows_metadata_only(
    sessionmaker: Sessions, test_database_url: str
) -> None:
    await register(sessionmaker)
    vault = vault_on(sessionmaker)
    await vault.set("acme", "mail", {"X-Api-Key": API_KEY})
    await vault.set("acme", "crm", {"X-Api-Key": "alice-crm-key-0123456"}, "alice")
    [(_, _, ciphertext, _), *_] = await rows(sessionmaker)

    plain = await invoke(test_database_url, ["cred", "list"], KEYSTONE_MASTER_KEYS=MASTER)
    as_json = await invoke(
        test_database_url, ["cred", "list", "--json"], KEYSTONE_MASTER_KEYS=MASTER
    )

    assert plain.exit_code == 0 and as_json.exit_code == 0
    header, crm, mail = plain.output.splitlines()
    assert header.split()[:4] == ["TENANT", "UPSTREAM", "USER", "KEY"]
    assert crm.split()[:4] == ["acme", "crm", "alice", key_id(MASTER)]
    assert mail.split()[:4] == ["acme", "mail", "-", key_id(MASTER)]
    listed = json.loads(as_json.output)
    assert [(r["upstream"], r["user"]) for r in listed] == [("crm", "alice"), ("mail", None)]
    for output in (plain.output, as_json.output):
        assert API_KEY not in output and "alice-crm-key" not in output
        assert ciphertext.decode() not in output and "gAAAA" not in output


@pytest.mark.phase(3)
async def test_cred_list_needs_no_master_key_and_says_so_when_empty(
    sessionmaker: Sessions, test_database_url: str
) -> None:
    await register(sessionmaker)

    result = await invoke(test_database_url, ["cred", "list"])

    assert result.exit_code == 0 and "no credentials stored" in result.output


@pytest.mark.phase(3)
async def test_rotate_keys_reencrypts_every_row_and_the_old_key_can_go(
    sessionmaker: Sessions, test_database_url: str
) -> None:
    await register(sessionmaker)
    new = Fernet.generate_key().decode()
    await vault_on(sessionmaker).set("acme", "mail", {"X-Api-Key": API_KEY})
    await vault_on(sessionmaker).set("acme", "crm", {"X-Api-Key": "alice-crm-key-0123456"}, "alice")
    before = await rows(sessionmaker)

    rotated = await invoke(
        test_database_url, ["cred", "rotate-keys"], KEYSTONE_MASTER_KEYS=f"{new},{MASTER}"
    )
    again = await invoke(
        test_database_url, ["cred", "rotate-keys"], KEYSTONE_MASTER_KEYS=f"{new},{MASTER}"
    )

    assert rotated.exit_code == 0, rotated.output
    assert "rotated 2, already under the first key 0" in rotated.output
    assert "rotated 0, already under the first key 2" in again.output
    after = await rows(sessionmaker)
    assert [row[3] for row in after] == [key_id(new)] * 2
    assert [row[2] for row in after] != [row[2] for row in before]
    # With the old key removed, everything still decrypts.
    found = await vault_on(sessionmaker, new).headers_for("acme", "mail", "alice")
    assert found["X-Api-Key"].get_secret_value() == API_KEY


@pytest.mark.phase(3)
async def test_rotate_keys_exits_1_when_a_row_cannot_be_decrypted(
    sessionmaker: Sessions, test_database_url: str
) -> None:
    await register(sessionmaker)
    await vault_on(sessionmaker, Fernet.generate_key().decode()).set(
        "acme", "mail", {"X-Api-Key": API_KEY}
    )

    result = await invoke(
        test_database_url,
        ["cred", "rotate-keys"],
        KEYSTONE_MASTER_KEYS=f"{Fernet.generate_key().decode()},{MASTER}",
    )

    assert result.exit_code == 1
    assert "could not decrypt 1" in result.output


@pytest.mark.phase(3)
async def test_rotation_does_not_undo_a_credential_set_meanwhile(sessionmaker: Sessions) -> None:
    await register(sessionmaker)
    old, new = MASTER, Fernet.generate_key().decode()
    await vault_on(sessionmaker, old).set("acme", "mail", {"X-Api-Key": API_KEY})
    repo = CredentialRepo(sessionmaker)
    [(row_id, stale, _)] = await repo.rows()

    await vault_on(sessionmaker, f"{new},{old}").set(
        "acme", "mail", {"X-Api-Key": "fresh-key-0123456789"}
    )
    renewed, kid = Cipher(f"{new},{old}").rotate(stale)
    swapped = await repo.replace(row_id, stale, renewed, kid)

    assert swapped is False
    found = await vault_on(sessionmaker, new).headers_for("acme", "mail", "alice")
    assert found["X-Api-Key"].get_secret_value() == "fresh-key-0123456789"
