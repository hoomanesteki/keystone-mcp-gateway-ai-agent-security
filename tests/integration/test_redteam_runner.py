"""KS-902: the red-team runner against real gateways, with no key.

Two gateways are started over the same four demo upstreams: one in the passthrough profile (C0) and
one with the policies, the approvals and the scanner (C2). The naive agent runs two scenarios in
each, as the runner does for the full matrix: an attack that the poisoned email asks for, and the
same task with no attack. The files the runner writes are read back the way the report reads them.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from eval.redteam import report
from eval.redteam.runner import (
    ConfigMismatch,
    LlmAgent,
    NaiveAgent,
    Target,
    Tokens,
    run_matrix,
    run_once,
)
from eval.redteam.schema import Upstream
from eval.redteam.suite import by_id, load_scenarios
from keystone.registry.config import UpstreamConfig
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.fake_llm import FakeLlm
from tests.fixtures.keystone import KeystoneApp, demo_tools
from tests.fixtures.redteam import RedTeamUpstreams

pytestmark = [pytest.mark.phase(9), pytest.mark.services]

Factory = Callable[..., KeystoneApp]
ATTACK = "mail_invoice.exfil_email"
BENIGN = "mail_invoice.benign"
UPSTREAMS: tuple[Upstream, ...] = ("mail", "files", "bank", "web")


def gateway(factory: Factory, upstreams: RedTeamUpstreams, **options: Any) -> KeystoneApp:
    """Keystone over the four red-team upstreams, with the demo tool classification."""
    configs = [
        UpstreamConfig(id=name, tenant="acme", url=upstreams.mcp(name), tools=demo_tools(name))
        for name in UPSTREAMS
    ]
    settings = {"upstreams": configs, **options.pop("settings", {})}
    return factory(settings=settings, **options)


def target(app: KeystoneApp, upstreams: RedTeamUpstreams, idp: FakeIdp, **more: Any) -> Target:
    return Target(
        base_url=app.base,
        witness=upstreams.witness,
        tokens=Tokens(
            agent=lambda: idp.token_for("olivia"),
            approver=lambda: idp.token_for("lena"),
            admin=lambda: idp.token_for("root"),
        ),
        **more,
    )


def lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def scenarios(*ids: str) -> list[Any]:
    found = by_id(load_scenarios())
    return [found[i] for i in ids]


async def test_runner_naive_c0_vs_c2_smoke(
    keystone_app_factory: Factory,
    redteam_upstreams: RedTeamUpstreams,
    fake_idp: FakeIdp,
    tmp_path: Path,
) -> None:
    baseline = gateway(keystone_app_factory, redteam_upstreams, settings={"profile": "passthrough"})
    full = gateway(keystone_app_factory, redteam_upstreams)
    chosen = scenarios(ATTACK, BENIGN)

    c0 = tmp_path / "c0.jsonl"
    c2 = tmp_path / "c2.jsonl"
    await run_matrix(
        chosen, "C0", NaiveAgent(), target(baseline, redteam_upstreams, fake_idp), c0, subset=True
    )
    await run_matrix(
        chosen, "C2", NaiveAgent(), target(full, redteam_upstreams, fake_idp), c2, subset=True
    )

    [start0, attack0, benign0, end0] = lines(c0)
    [start2, attack2, benign2, end2] = lines(c2)
    # Without a defense the poisoned email is obeyed and the mail goes out; with all of them it does
    # not. Both are read from the mail server's own record, not from what the agent said.
    assert attack0["attack_success"] is True and attack0["obeyed"] == 1
    assert attack2["attack_success"] is False and attack2["obeyed"] == 1
    # The same task with no attack is done in both, and a person was asked only in C2's attack.
    assert benign0["utility_success"] is True and benign2["utility_success"] is True
    assert benign0["attack_success"] is None and benign2["attack_success"] is None
    assert attack0["approvals"]["requested"] == 0
    assert attack2["approvals"]["requested"] >= 1 and attack2["approvals"]["approved"] == 0
    assert "KS_APPROVAL_REJECTED" in attack2["error_codes"]
    [decision, *_] = attack2["approvals"]["decisions"]
    assert decision["tool"] == "mail__send_email" and decision["approved"] is False
    # Two rules asked, and the card says which: acme's rule for mail to outside addresses, and the
    # Rule of Two, since the session had read untrusted and sensitive data.
    assert decision["reasons"] == ["external-email-needs-approval", "rule-of-two"]
    assert decision["flags"] == ["reads_sensitive", "reads_untrusted"]
    # What the file says about itself.
    assert (start0["config"], start0["gateway"]["profile"], start0["gateway"]["scanner"]) == (
        "C0",
        "passthrough",
        "off",
    )
    assert (start2["config"], start2["gateway"]["profile"], start2["gateway"]["scanner"]) == (
        "C2",
        "full",
        "on",
    )
    assert start2["scenarios"] == 2 and start2["subset"] is True
    assert (end0["runs"], end0["aborted"]) == (2, None) and end2["runs"] == 2
    # The session the run opened is read back from the admin API: tainted or flagged in C2 only.
    assert attack0["session"]["flags"] == [] and attack0["session"]["tainted"] is False
    assert attack2["session"]["flags"] == ["reads_sensitive", "reads_untrusted"]
    # The scores the scanner gave the outputs of the session come from its audit records: none in
    # C0, which scans nothing, and a score for each output that was read in C2.
    assert attack0["session"]["scans"] == []
    scanned = {scan["tool"]: scan for scan in attack2["session"]["scans"]}
    assert {"mail__list_emails", "mail__read_email"} <= set(scanned)
    assert scanned["mail__read_email"]["score"] > scanned["mail__list_emails"]["score"] >= 0
    assert scanned["mail__read_email"]["action"] in {"annotate", "redact", "block"}


async def test_the_report_reads_what_the_runner_wrote(
    keystone_app_factory: Factory,
    redteam_upstreams: RedTeamUpstreams,
    fake_idp: FakeIdp,
    tmp_path: Path,
) -> None:
    baseline = gateway(keystone_app_factory, redteam_upstreams, settings={"profile": "passthrough"})
    out = tmp_path / "redteam-naive-C0-test.jsonl"
    await run_matrix(
        scenarios(ATTACK, BENIGN),
        "C0",
        NaiveAgent(),
        target(baseline, redteam_upstreams, fake_idp),
        out,
    )

    file = report.read_results(out)
    stats = report.aggregate(file.runs)

    assert file.complete and file.usable
    assert (stats["asr"]["k"], stats["asr"]["n"]) == (1, 1)
    assert (stats["benign_utility"]["k"], stats["benign_utility"]["n"]) == (1, 1)
    assert report.how_it_ended(file.runs[0]) == "landed"
    assert "| Naive | C0 passthrough | 1 of 1 |" in report.render_section([file])


async def test_the_runner_refuses_a_gateway_that_is_not_the_config_it_was_told(
    keystone_app_factory: Factory,
    redteam_upstreams: RedTeamUpstreams,
    fake_idp: FakeIdp,
    tmp_path: Path,
) -> None:
    baseline = gateway(keystone_app_factory, redteam_upstreams, settings={"profile": "passthrough"})
    out = tmp_path / "wrong.jsonl"

    with pytest.raises(ConfigMismatch, match="this is not C2: its profile is passthrough"):
        await run_matrix(
            scenarios(ATTACK),
            "C2",
            NaiveAgent(),
            target(baseline, redteam_upstreams, fake_idp),
            out,
        )

    assert not out.exists()  # nothing is written for a label that is not true


async def test_a_result_file_is_never_added_to(
    keystone_app_factory: Factory,
    redteam_upstreams: RedTeamUpstreams,
    fake_idp: FakeIdp,
    tmp_path: Path,
) -> None:
    baseline = gateway(keystone_app_factory, redteam_upstreams, settings={"profile": "passthrough"})
    out = tmp_path / "once.jsonl"
    where = target(baseline, redteam_upstreams, fake_idp)
    await run_matrix(scenarios(BENIGN), "C0", NaiveAgent(), where, out)
    before = out.read_text(encoding="utf-8")

    with pytest.raises(FileExistsError):
        await run_matrix(scenarios(BENIGN), "C0", NaiveAgent(), where, out)

    assert out.read_text(encoding="utf-8") == before


async def test_a_run_that_is_cut_off_by_the_budget_of_the_runner_is_said_in_the_file(
    keystone_app_factory: Factory,
    redteam_upstreams: RedTeamUpstreams,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Path,
    tmp_path: Path,
) -> None:
    app = gateway(
        keystone_app_factory,
        redteam_upstreams,
        settings={"llm_proxy": fake_llm.settings(fake_prices)},
        environ=fake_llm.environ(),
    )
    agent = LlmAgent(model="fake-agent", script_hint=True)
    out = tmp_path / "llm.jsonl"

    progress = await run_matrix(
        scenarios(BENIGN, ATTACK, "mail_reply.benign"),
        "C2",
        agent,
        target(app, redteam_upstreams, fake_idp, database_url=app.database_url),
        out,
        # One run costs a few thousandths of a cent at the fake prices, so a limit of a hundredth
        # of a cent stops the batch after the first run.
        max_usd=0.0000001,
        seeds=2,
    )

    [start, only, end] = lines(out)
    assert progress.runs == 1 and progress.aborted is not None
    assert start["model"] == "fake-agent" and start["agent"] == "llm"
    assert only["cost_usd"] > 0 and only["turns"] >= 3 and only["input_tokens"] > 0
    assert end["aborted"] == progress.aborted and end["runs"] == 1


async def test_the_cost_of_a_run_is_the_ledger_rows_of_its_requests(
    keystone_app_factory: Factory,
    redteam_upstreams: RedTeamUpstreams,
    fake_idp: FakeIdp,
    fake_llm: FakeLlm,
    fake_prices: Path,
) -> None:
    app = gateway(
        keystone_app_factory,
        redteam_upstreams,
        settings={"llm_proxy": fake_llm.settings(fake_prices)},
        environ=fake_llm.environ(),
    )
    agent = LlmAgent(model="fake-agent", script_hint=True)
    where = target(app, redteam_upstreams, fake_idp, database_url=app.database_url)
    [scenario] = scenarios(BENIGN)

    async with httpx.AsyncClient(base_url=app.base, timeout=30) as client:
        first = await run_once(scenario, "C2", agent, 1, where, client)
        second = await run_once(scenario, "C2", agent, 2, where, client)

    # Each run is booked on its own: the same task twice costs the same, and each is what its own
    # requests cost and not what the ledger held so far.
    assert first["cost_usd"] > 0
    assert first["cost_usd"] == pytest.approx(second["cost_usd"], rel=0.05)
    assert (first["seed"], second["seed"]) == (1, 2)
    assert first["agent"] == "llm" and first["model"] == "fake-agent"
    assert first["stopped"] == "done"
