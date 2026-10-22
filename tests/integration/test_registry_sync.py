"""KS-203: tool discovery and sync."""

import anyio
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keystone.core.canonical import canonical_json, sha256_hex
from keystone.core.errors import Code, Reject
from keystone.core.types import Risk, ToolStatus, ToolTag
from keystone.registry.config import ToolOverride
from keystone.registry.sync import REMOVED
from tests.fixtures.registry import FakeUpstream, running_registry, tool
from tests.fixtures.upstreams import NAMES, DemoUpstreams

pytestmark = [pytest.mark.phase(2), pytest.mark.services]

Sessions = async_sessionmaker[AsyncSession]


async def test_sync_creates_tools_with_hashes(
    sessionmaker: Sessions, demo_upstreams: DemoUpstreams
) -> None:
    urls = {name: demo_upstreams.url(name) for name in NAMES}
    async with running_registry(sessionmaker, urls=urls) as env:
        reports = await env.service.sync_all()
        listed = await env.service.list_for_tenant("acme")

    assert [r.upstream_id for r in reports] == sorted(NAMES)
    assert all(r.ok and len(r.created) == 3 for r in reports), reports
    assert len(listed) == 12
    for ref in listed:
        assert ref.description_hash and ref.schema_hash
        assert ref.description_hash == sha256_hex(canonical_json(ref.description))
        assert ref.schema_hash == sha256_hex(canonical_json(ref.input_schema))
        assert ref.name == f"{ref.upstream_id}__{ref.upstream_tool_name}"
        assert (ref.status, ref.risk, ref.tags) == (ToolStatus.ACTIVE, Risk.MEDIUM, frozenset())
    rows = {row.id: row for row in await env.upstreams.list()}
    assert {row.status for row in rows.values()} == {"up"}
    assert all(row.last_sync_at is not None and row.last_error is None for row in rows.values())


async def test_config_overrides_applied(
    sessionmaker: Sessions, demo_upstreams: DemoUpstreams
) -> None:
    overrides = {
        "mail": {
            "send_email": ToolOverride(
                risk=Risk.HIGH,
                tags=[ToolTag.EXTERNAL_EFFECT],
                cost_per_call_usd=0.01,
                timeout_s=5,
                extract={"recipient_domain": "$.to | domain"},
            ),
            "read_email": ToolOverride(tags=[ToolTag.READS_UNTRUSTED, ToolTag.READS_SENSITIVE]),
            "not_a_tool": ToolOverride(risk=Risk.CRITICAL),  # named but absent: logged, no effect
        }
    }
    async with running_registry(
        sessionmaker, urls={"mail": demo_upstreams.url("mail")}, overrides=overrides
    ) as env:
        await env.service.sync_all()
        send = await env.service.get("acme", "mail__send_email")
        read = await env.service.get("acme", "mail__read_email")
        plain = await env.service.get("acme", "mail__list_emails")

    assert send is not None and read is not None and plain is not None
    assert send.risk is Risk.HIGH
    assert send.tags == frozenset({ToolTag.EXTERNAL_EFFECT})
    assert (send.cost_per_call_usd, send.timeout_s) == (0.01, 5.0)
    assert send.extractors == {"recipient_domain": "$.to | domain"}
    assert read.risk is Risk.MEDIUM
    assert read.tags == frozenset({ToolTag.READS_UNTRUSTED, ToolTag.READS_SENSITIVE})
    # No override: the defaults.
    assert (plain.risk, plain.tags, plain.cost_per_call_usd, plain.timeout_s) == (
        Risk.MEDIUM,
        frozenset(),
        0.0,
        30.0,
    )


async def test_overrides_follow_the_config_on_the_next_sync(sessionmaker: Sessions) -> None:
    fleet = {"mail": FakeUpstream(tool("send_email"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        await env.service.sync_all()
        before = await env.service.get("acme", "mail__send_email")

        env.syncer.overrides = {"mail": {"send_email": ToolOverride(risk=Risk.HIGH)}}
        report = await env.service.sync_all()
        after = await env.service.get("acme", "mail__send_email")

    assert before is not None and after is not None
    assert (before.risk, after.risk) == (Risk.MEDIUM, Risk.HIGH)
    assert report[0].unchanged == ["mail__send_email"]
    assert after.description_hash == before.description_hash


async def test_removed_tool_disabled(sessionmaker: Sessions) -> None:
    fleet = {"mail": FakeUpstream(tool("read"), tool("send"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        await env.service.sync_all()

        fleet["mail"].tools = [tool("read")]
        report = (await env.service.sync_all())[0]

        listed = [t.name for t in await env.service.list_for_tenant("acme")]
        gone = await env.service.get("acme", "mail__send")
        row = await env.tools.get("acme", "mail__send")

    assert report.removed == ["mail__send"]
    assert listed == ["mail__read"]
    # The row is kept, so audit records that name the tool still resolve.
    assert gone is not None and gone.status is ToolStatus.DISABLED
    assert row is not None and row.quarantine_reason == REMOVED


async def test_a_removed_tool_that_comes_back_unchanged_is_active_again(
    sessionmaker: Sessions,
) -> None:
    fleet = {"mail": FakeUpstream(tool("read"), tool("send"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        await env.service.sync_all()
        fleet["mail"].tools = [tool("read")]
        await env.service.sync_all()

        fleet["mail"].tools = [tool("read"), tool("send")]
        report = (await env.service.sync_all())[0]
        listed = [t.name for t in await env.service.list_for_tenant("acme")]
        row = await env.tools.get("acme", "mail__send")

    assert report.unchanged == ["mail__read", "mail__send"]
    assert listed == ["mail__read", "mail__send"]
    assert row is not None and row.quarantine_reason is None


async def test_a_tool_an_operator_disabled_stays_disabled(sessionmaker: Sessions) -> None:
    fleet = {"mail": FakeUpstream(tool("read"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        await env.service.sync_all()
        await env.tools.set_status("acme", "mail__read", ToolStatus.DISABLED, reason="operator")

        report = (await env.service.sync_all())[0]
        env.service.invalidate()
        ref = await env.service.get("acme", "mail__read")

    assert report.unchanged == ["mail__read"]
    assert ref is not None and ref.status is ToolStatus.DISABLED


async def test_sync_report_lists_changes(sessionmaker: Sessions) -> None:
    fleet = {"mail": FakeUpstream(tool("a"), tool("b"), tool("c"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        first = (await env.service.sync_all())[0]
        again = (await env.service.sync_all())[0]

        fleet["mail"].tools = [
            tool("a"),  # unchanged
            tool("b", description="b now does something else"),  # description changed
            tool("d"),  # new; c is gone
        ]
        third = (await env.service.sync_all())[0]
        fourth = (await env.service.sync_all())[0]

        schema_change = {"type": "object", "properties": {"id": {"type": "integer"}}}
        fleet["mail"].tools = [tool("a", schema=schema_change), tool("b"), tool("d")]
        fifth = (await env.service.sync_all())[0]

    assert first.created == ["mail__a", "mail__b", "mail__c"]
    assert first.ok and first.unchanged == first.changed == first.removed == []
    assert again.unchanged == ["mail__a", "mail__b", "mail__c"]
    assert again.created == again.changed == again.removed == []
    assert third.created == ["mail__d"]
    assert third.unchanged == ["mail__a"]
    assert third.changed == ["mail__b"]
    assert third.removed == ["mail__c"]
    # The description change is only reported until pinning acts on it (KS-205): the stored
    # definition is the old one, so it is reported again.
    assert fourth.changed == ["mail__b"]
    assert fifth.changed == ["mail__a"]


async def test_a_tool_name_that_cannot_be_exposed_is_reported_and_skipped(
    sessionmaker: Sessions,
) -> None:
    fleet = {"mail": FakeUpstream(tool("read.email"), tool("read_email"), tool("x" * 70))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        report = (await env.service.sync_all())[0]
        listed = [t.name for t in await env.service.list_for_tenant("acme")]

    assert listed == ["mail__read_email"]
    assert report.created == ["mail__read_email"]
    assert len(report.errors) == 2
    assert all("cannot be exposed" in e for e in report.errors)


async def test_a_tool_listed_twice_is_stored_once(sessionmaker: Sessions) -> None:
    fleet = {"mail": FakeUpstream(tool("read"), tool("read", description="again"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        report = (await env.service.sync_all())[0]
        ref = await env.service.get("acme", "mail__read")

    assert report.created == ["mail__read"]
    assert report.errors == ["tool 'mail__read' is listed twice"]
    assert ref is not None and ref.description == "read does a thing"


# The gate asks that a sync error on one upstream never disables the tools of the others.


async def test_a_sync_error_on_one_upstream_changes_no_tool_anywhere(
    sessionmaker: Sessions,
) -> None:
    fleet = {
        "mail": FakeUpstream(tool("read"), tool("send")),
        "bank": FakeUpstream(tool("balance"), tool("transfer")),
        "echo": FakeUpstream(tool("echo")),
    }
    async with running_registry(sessionmaker, fleet=fleet) as env:
        await env.service.sync_all()
        before = {r.name: r for r in await env.tools.list_by_tenant("acme")}
        assert len(before) == 5

        # Bank breaks in each way an upstream can. Mail and echo change underneath it.
        failures: list[BaseException] = [
            Reject(Code.UPSTREAM_ERROR, "the upstream server is not reachable"),
            Reject(Code.UPSTREAM_TIMEOUT, "the upstream server did not list its tools"),
            RuntimeError("boom"),
            ConnectionResetError("connection reset"),
        ]
        for failure in failures:
            fleet["bank"].error = failure
            fleet["mail"].tools = [tool("read")]  # send disappears: a legitimate removal
            fleet["echo"].tools = [tool("echo", description="changed")]
            reports = {r.upstream_id: r for r in await env.service.sync_all()}
            fleet["mail"].tools = [tool("read"), tool("send")]  # reset for the next round
            await env.service.sync_all()

            assert not reports["bank"].ok
            assert reports["mail"].ok and reports["mail"].removed == ["mail__send"]
            assert reports["echo"].ok and reports["echo"].changed == ["echo__echo"]
            fleet["bank"].error = None

        fleet["bank"].error = RuntimeError("boom")
        await env.service.sync_all()
        after = {r.name: r for r in await env.tools.list_by_tenant("acme")}

    # The failing upstream's own tools are untouched: a failed list proves nothing was removed.
    for name in ("bank__balance", "bank__transfer"):
        assert after[name].status == "active"
        assert after[name].description_hash == before[name].description_hash
    # And the others are exactly as healthy syncs left them.
    assert after["mail__read"].status == after["mail__send"].status == "active"
    assert after["echo__echo"].status == "active"


async def test_a_failed_sync_records_the_error_and_keeps_the_last_good_time(
    sessionmaker: Sessions,
) -> None:
    fleet = {"mail": FakeUpstream(tool("read")), "bank": FakeUpstream(tool("balance"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        await env.service.sync_all()
        good = {r.id: r.last_sync_at for r in await env.upstreams.list()}

        fleet["bank"].error = Reject(Code.UPSTREAM_ERROR, "the upstream server is not reachable")
        reports = {r.upstream_id: r for r in await env.service.sync_all()}
        rows = {r.id: r for r in await env.upstreams.list()}

        fleet["bank"].error = None
        await env.service.sync_all()
        recovered = {r.id: r for r in await env.upstreams.list()}

    assert reports["bank"].errors == ["KS_UPSTREAM_ERROR: the upstream server is not reachable"]
    assert rows["bank"].last_error == "KS_UPSTREAM_ERROR: the upstream server is not reachable"
    assert rows["bank"].last_sync_at == good["bank"]
    assert rows["mail"].last_error is None
    mail_time, bank_time, old_mail, old_bank = (
        rows["mail"].last_sync_at,
        recovered["bank"].last_sync_at,
        good["mail"],
        good["bank"],
    )
    assert mail_time is not None and old_mail is not None and mail_time > old_mail
    assert recovered["bank"].last_error is None
    assert bank_time is not None and old_bank is not None and bank_time > old_bank


async def test_an_exception_message_never_reaches_last_error(sessionmaker: Sessions) -> None:
    fleet = {"mail": FakeUpstream(tool("read"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        fleet["mail"].error = RuntimeError("GET http://mail/?api_key=hunter2 failed")
        report = (await env.service.sync_all())[0]
        row = await env.upstreams.get("mail")

    assert report.errors == ["sync failed (RuntimeError)"]
    assert row is not None and row.last_error == "sync failed (RuntimeError)"


async def test_a_hanging_upstream_times_out_without_holding_up_the_others(
    sessionmaker: Sessions,
) -> None:
    fleet = {"mail": FakeUpstream(tool("read")), "bank": FakeUpstream(tool("balance"))}
    async with running_registry(sessionmaker, fleet=fleet, timeout_s=0.3) as env:
        await env.service.sync_all()
        fleet["bank"].hang = True

        reports = {r.upstream_id: r for r in await env.service.sync_all()}
        row = await env.tools.get("acme", "bank__balance")

    assert reports["bank"].errors == ["the sync timed out"]
    assert reports["mail"].ok
    assert row is not None and row.status == "active"


async def test_syncing_an_unknown_or_disabled_upstream_reports_instead_of_raising(
    sessionmaker: Sessions,
) -> None:
    fleet = {"mail": FakeUpstream(tool("read"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        await env.upstreams.set_status("mail", "disabled")

        unknown = await env.service.sync_upstream("ghost")
        disabled = await env.service.sync_upstream("mail")
        everything = await env.service.sync_all()

    assert unknown.errors == ["there is no such upstream"]
    assert disabled.errors == ["the upstream is disabled"]
    assert everything == []
    assert fleet["mail"].listings == 0


async def test_a_disabled_upstream_hides_its_tools_and_a_sync_does_not_revive_it(
    sessionmaker: Sessions,
) -> None:
    fleet = {"mail": FakeUpstream(tool("read")), "bank": FakeUpstream(tool("balance"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        await env.service.sync_all()
        await env.upstreams.set_status("bank", "disabled")
        env.service.invalidate()

        listed = [t.name for t in await env.service.list_for_tenant("acme")]
        hidden = await env.service.get("acme", "bank__balance")
        await env.service.sync_all()
        row = await env.upstreams.get("bank")

    assert listed == ["mail__read"]
    assert hidden is None
    assert row is not None and row.status == "disabled"


async def test_a_sync_marks_a_reachable_upstream_up_but_not_a_disabled_one(
    sessionmaker: Sessions,
) -> None:
    fleet = {"mail": FakeUpstream(tool("read"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        await env.upstreams.set_status("mail", "down")
        await env.service.sync_all()
        up = await env.upstreams.get("mail")
        await env.upstreams.set_status("mail", "disabled")
        await env.service.sync_all()
        disabled = await env.upstreams.get("mail")

    assert up is not None and up.status == "up"
    assert disabled is not None and disabled.status == "disabled"


async def test_the_cache_is_dropped_by_a_sync_and_expires_by_time(sessionmaker: Sessions) -> None:
    fleet = {"mail": FakeUpstream(tool("read"))}
    now = [0.0]
    async with running_registry(
        sessionmaker, fleet=fleet, cache_ttl_s=10.0, clock=lambda: now[0]
    ) as env:
        await env.service.sync_all()
        assert [t.name for t in await env.service.list_for_tenant("acme")] == ["mail__read"]

        # A change made behind the service's back (another process) waits for the time limit.
        await env.tools.set_status("acme", "mail__read", ToolStatus.QUARANTINED, reason="x")
        now[0] = 9.0
        stale = [t.name for t in await env.service.list_for_tenant("acme")]
        now[0] = 11.0
        fresh = [t.name for t in await env.service.list_for_tenant("acme")]

        # A sync in this process drops the snapshot at once.
        await env.tools.set_status("acme", "mail__read", ToolStatus.ACTIVE)
        await env.service.sync_all()
        after_sync = [t.name for t in await env.service.list_for_tenant("acme")]

    assert (stale, fresh, after_sync) == (["mail__read"], [], ["mail__read"])


async def test_a_tenant_only_sees_its_own_tools(sessionmaker: Sessions) -> None:
    fleet = {"mail": FakeUpstream(tool("read"))}
    async with running_registry(sessionmaker, fleet=fleet) as env:
        await env.service.sync_all()

        assert await env.service.list_for_tenant("globex") == []
        assert await env.service.get("globex", "mail__read") is None


async def test_periodic_sync_retries_an_upstream_that_was_down(sessionmaker: Sessions) -> None:
    fleet = {"mail": FakeUpstream(tool("read")), "bank": FakeUpstream(tool("balance"))}
    fleet["bank"].error = Reject(Code.UPSTREAM_ERROR, "the upstream server is not reachable")
    async with running_registry(sessionmaker, fleet=fleet) as env:
        first = await env.service.sync_all()
        assert [r.upstream_id for r in first if not r.ok] == ["bank"]
        assert [t.name for t in await env.service.list_for_tenant("acme")] == ["mail__read"]

        async with anyio.create_task_group() as group:
            group.start_soon(env.service.run_periodic, 0.05)
            fleet["bank"].error = None
            with anyio.fail_after(5):
                while len(await env.service.list_for_tenant("acme")) < 2:  # noqa: ASYNC110
                    await anyio.sleep(0.05)
            group.cancel_scope.cancel()

    assert fleet["bank"].listings >= 2
