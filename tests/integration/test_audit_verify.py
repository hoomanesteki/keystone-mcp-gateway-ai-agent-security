"""KS-503: `keystone audit verify`, `keystone audit export`, and the role the app runs as."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import asyncpg
import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.audit.sink import PostgresAuditSink
from keystone.core.canonical import canonical_json
from keystone.core.types import Decision, Effect, Principal
from tests.fixtures.calls import OLIVIA, make_ctx
from tests.fixtures.cli import invoke
from tests.fixtures.db import APP_ROLE

pytestmark = [pytest.mark.phase(5), pytest.mark.services]

Sessionmaker = async_sessionmaker[AsyncSession]
GLOBEX = Principal(tenant_id="globex", user_id="bob", agent_id="support-agent")


async def write(sessions: Sessionmaker, count: int, **kwargs: Any) -> None:
    """`count` calls through a real writer, olivia of acme unless told otherwise."""
    async with PostgresAuditSink(sessions) as sink:
        for n in range(count):
            ctx = make_ctx(
                {"text": f"call {n}"},
                decision=Decision(effect=Effect.ALLOW, reasons=["rule"], source="policy"),
                dispatched=True,
                cost_usd=0.01 * n,
                **kwargs,
            )
            await sink.record(ctx, "ok", None)
        await sink.flush()


async def as_owner(url: str, sql: str) -> str:
    """Run one statement as the role that owns the tables, which can do what the app cannot."""
    connection = await asyncpg.connect(url.replace("postgresql+asyncpg://", "postgresql://", 1))
    try:
        return await connection.execute(sql)
    finally:
        await connection.close()


async def test_verify_ok(
    clean_env: None, test_database_url: str, sessionmaker: Sessionmaker
) -> None:
    await write(sessionmaker, 42)

    result = await invoke(test_database_url, ["audit", "verify"])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == "OK, 42 records"
    # From the middle: the row before is the anchor, and the rows from there on are checked.
    middle = await invoke(test_database_url, ["audit", "verify", "--from-seq", "30"])
    assert middle.exit_code == 0 and middle.output.strip() == "OK, 13 records"


async def test_verify_ok_on_an_empty_log_and_one_record(
    clean_env: None, test_database_url: str, sessionmaker: Sessionmaker
) -> None:
    empty = await invoke(test_database_url, ["audit", "verify"])
    await write(sessionmaker, 1)
    one = await invoke(test_database_url, ["audit", "verify"])

    assert (empty.exit_code, empty.output.strip()) == (0, "OK, 0 records")
    assert (one.exit_code, one.output.strip()) == (0, "OK, 1 record")


@pytest.mark.parametrize(
    "edit",
    [
        "tool_name = 'x'",
        "user_id = 'mallory'",
        "tenant_id = 'globex'",
        "effect = 'deny'",
        "reasons = ARRAY['other']",
        "outcome = 'rejected'",
        "dispatched = false",
        "cost_usd = 99",
        "ts = ts + interval '1 microsecond'",
        "args_redacted = '{\"x\": 1}'::jsonb",
        "trace_id = 'abc'",
        "hash = repeat('a', 64)",
        "prev_hash = repeat('b', 64)",
    ],
)
async def test_verify_detects_tampering(
    clean_env: None, test_database_url: str, sessionmaker: Sessionmaker, edit: str
) -> None:
    await write(sessionmaker, 12)
    await as_owner(test_database_url, f"UPDATE audit_events SET {edit} WHERE seq = 10")  # noqa: S608 - fixed test cases

    result = await invoke(test_database_url, ["audit", "verify"])

    assert result.exit_code == 2, result.output
    assert result.output.strip() == "broken at seq 10: hash mismatch"


async def test_verify_detects_deleted_row(
    clean_env: None, test_database_url: str, sessionmaker: Sessionmaker
) -> None:
    await write(sessionmaker, 12)
    await as_owner(test_database_url, "DELETE FROM audit_events WHERE seq = 5")
    in_the_middle = await invoke(test_database_url, ["audit", "verify"])
    await as_owner(test_database_url, "DELETE FROM audit_events WHERE seq = 1")
    at_the_start = await invoke(test_database_url, ["audit", "verify"])

    assert in_the_middle.exit_code == 2
    assert in_the_middle.output.strip() == "broken at seq 5: gap"
    assert at_the_start.exit_code == 2
    assert at_the_start.output.strip() == "broken at seq 1: gap"


async def test_verify_from_seq_checks_only_from_there(
    clean_env: None, test_database_url: str, sessionmaker: Sessionmaker
) -> None:
    await write(sessionmaker, 12)
    await as_owner(test_database_url, "UPDATE audit_events SET tool_name = 'x' WHERE seq = 3")

    before = await invoke(test_database_url, ["audit", "verify"])
    after = await invoke(test_database_url, ["audit", "verify", "--from-seq", "5"])
    await as_owner(test_database_url, "UPDATE audit_events SET tool_name = 'y' WHERE seq = 7")
    inside = await invoke(test_database_url, ["audit", "verify", "--from-seq", "5"])
    await as_owner(test_database_url, "DELETE FROM audit_events WHERE seq = 4")
    anchor_gone = await invoke(test_database_url, ["audit", "verify", "--from-seq", "5"])

    assert before.output.strip() == "broken at seq 3: hash mismatch"
    assert (after.exit_code, after.output.strip()) == (0, "OK, 8 records")
    assert inside.output.strip() == "broken at seq 7: hash mismatch"
    assert anchor_gone.output.strip() == "broken at seq 4: gap"


async def test_verify_does_not_see_missing_newest_rows(
    clean_env: None, test_database_url: str, sessionmaker: Sessionmaker
) -> None:
    # What the chain cannot prove (ADR-0009): a log that was cut short is still a whole chain.
    await write(sessionmaker, 12)
    await as_owner(test_database_url, "DELETE FROM audit_events WHERE seq > 8")

    result = await invoke(test_database_url, ["audit", "verify"])

    assert (result.exit_code, result.output.strip()) == (0, "OK, 8 records")


async def test_app_role_cannot_update(
    clean_env: None,
    test_database_url: str,
    app_database_url: str,
    sessionmaker: Sessionmaker,
) -> None:
    await write(sessionmaker, 3)
    dsn = app_database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    assert make_url(app_database_url).username == APP_ROLE
    connection = await asyncpg.connect(dsn)
    try:
        assert await connection.fetchval("SELECT count(*) FROM audit_events") == 3
        for statement in (
            "UPDATE audit_events SET tool_name = 'x' WHERE seq = 1",
            "DELETE FROM audit_events WHERE seq = 1",
            "TRUNCATE audit_events",
        ):
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await connection.execute(statement)
        # What it may do: add a record (through the writer) and everything on the other tables.
        await connection.execute("UPDATE tenants SET name = name")
        await connection.execute("INSERT INTO tenants (id, name) VALUES ('t1', 'T1')")
        await connection.execute("DELETE FROM tenants WHERE id = 't1'")
        privileges = {
            row["privilege_type"]
            for row in await connection.fetch(
                "SELECT privilege_type FROM information_schema.role_table_grants "
                "WHERE grantee = 'keystone_app' AND table_name = 'audit_events'"
            )
        }
    finally:
        await connection.close()

    assert privileges == {"INSERT", "SELECT"}


async def test_a_table_made_later_is_open_to_the_app_role(
    clean_env: None, test_database_url: str, app_database_url: str, sessionmaker: Sessionmaker
) -> None:
    # Default privileges: a later migration creates tables as the owner, and the app can use them.
    await as_owner(test_database_url, "CREATE TABLE later_table (id serial PRIMARY KEY, v text)")
    connection = await asyncpg.connect(app_database_url.replace("+asyncpg", "", 1))
    try:
        await connection.execute("INSERT INTO later_table (v) VALUES ('a')")
        await connection.execute("UPDATE later_table SET v = 'b'")
        assert await connection.fetchval("SELECT v FROM later_table") == "b"
        await connection.execute("DELETE FROM later_table")
    finally:
        await connection.close()
        await as_owner(test_database_url, "DROP TABLE later_table")


async def test_the_app_role_cannot_touch_the_migration_state(
    clean_env: None, app_database_url: str
) -> None:
    connection = await asyncpg.connect(app_database_url.replace("+asyncpg", "", 1))
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await connection.fetchval("SELECT version_num FROM alembic_version")
    finally:
        await connection.close()


def parse(output: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in output.splitlines() if line.strip()]


def check_line(line: dict[str, Any], previous: str) -> None:
    """The documented way to check one exported record, with a JSON library and sha256 only."""
    body = {k: v for k, v in line.items() if k not in ("seq", "prev_hash", "hash")}
    assert line["prev_hash"] == previous
    expected = hashlib.sha256(bytes.fromhex(line["prev_hash"]) + canonical_json(body)).hexdigest()
    assert line["hash"] == expected


async def test_export_jsonl(
    clean_env: None, test_database_url: str, sessionmaker: Sessionmaker
) -> None:
    long_ago = datetime(2026, 10, 1, 8, 0, 0, tzinfo=UTC)
    await write(sessionmaker, 4, received_at=long_ago)
    await write(sessionmaker, 3, principal=GLOBEX, received_at=long_ago + timedelta(days=1))
    await write(sessionmaker, 5, received_at=long_ago + timedelta(days=2))

    everything = await invoke(test_database_url, ["audit", "export"])
    acme = await invoke(test_database_url, ["audit", "export", "--tenant", "acme"])
    window = await invoke(
        test_database_url,
        ["audit", "export", "--since", "2026-10-02", "--until", "2026-10-03T00:00:00Z"],
    )

    assert everything.exit_code == 0, everything.output
    lines = parse(everything.output)
    assert [line["seq"] for line in lines] == list(range(1, 13))
    previous = "0" * 64
    for line in lines:
        check_line(line, previous)  # a record proves itself, and the chain runs through the file
        previous = line["hash"]
    first = lines[0]
    assert first["tenant_id"] == "acme" and first["user_id"] == OLIVIA.user_id
    assert first["ts"] == "2026-10-01T08:00:00.000000Z"
    assert first["cost_usd"] == "0.00000000" and lines[2]["cost_usd"] == "0.02000000"
    assert first["reasons"] == ["rule"] and first["effect"] == "allow"
    assert first["args_redacted"] == {"text": "call 0"}
    assert [line["seq"] for line in parse(acme.output)] == [1, 2, 3, 4, 8, 9, 10, 11, 12]
    assert {line["tenant_id"] for line in parse(window.output)} == {"globex"}
    assert [line["seq"] for line in parse(window.output)] == [5, 6, 7]


async def test_export_of_an_empty_log_is_empty(clean_env: None, test_database_url: str) -> None:
    result = await invoke(test_database_url, ["audit", "export"])

    assert result.exit_code == 0 and result.output == ""


async def test_export_refuses_a_date_it_cannot_read(
    clean_env: None, test_database_url: str
) -> None:
    result = await invoke(test_database_url, ["audit", "export", "--since", "last tuesday"])

    assert result.exit_code == 1
    assert "--since" in result.output


async def test_the_database_error_text_is_not_printed(clean_env: None) -> None:
    result = await invoke(
        "postgresql+asyncpg://nobody:secret-pw-1234@127.0.0.1:1/none", ["audit", "verify"]
    )

    assert result.exit_code == 1
    assert "secret-pw-1234" not in result.output
