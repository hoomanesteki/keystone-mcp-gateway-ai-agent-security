import json
from pathlib import Path

import anyio
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from examples.agents.scripted_agent import Step, load_steps, main, run_script
from tests.fixtures.approvals import Approver
from tests.fixtures.fake_idp import FakeIdp
from tests.fixtures.keystone import KeystoneApp
from tests.fixtures.servers import ServerThread
from tests.fixtures.upstreams import DemoUpstreams

SCRIPTS = Path(__file__).resolve().parents[2] / "examples" / "agents" / "scripts"
DEMO = SCRIPTS / "demo_p1.yaml"


@pytest.mark.services
@pytest.mark.phase(1)
async def test_the_demo_script_runs_through_keystone(
    keystone_app: KeystoneApp, demo_upstreams: DemoUpstreams, fake_idp: FakeIdp
) -> None:
    # The script sends mail and reads a balance as an operator: olivia through ops-agent.
    transcript = await run_script(
        keystone_app.url, load_steps(DEMO), token=fake_idp.token_for("olivia")
    )

    assert transcript.ok
    assert [e.kind for e in transcript.entries] == ["list_tools"] + ["call_tool"] * 3
    assert "mail__read_email" in transcript.entries[0].tools
    balance, sent, read = transcript.calls
    assert "4825.5" in balance.text
    assert "colleague@acme.test" in sent.text
    assert "Invoice 4471" in read.text
    # Every call names itself, and the name is the one in the audit log.
    assert [c.call_id for c in transcript.calls] == [
        r["call_id"] for r in keystone_app.audit.records
    ]
    assert demo_upstreams.state("mail")["sent"] == [
        {
            "id": "s1",
            "to": "colleague@acme.test",
            "subject": "Q3 budget review",
            "body": "The Q3 numbers are in the reports folder. Operations is 4 percent over plan.",
        }
    ]


@pytest.mark.services
@pytest.mark.phase(1)
async def test_a_refusal_matches_expect_error_code_and_anything_else_fails(
    keystone_app: KeystoneApp, fake_idp: FakeIdp
) -> None:
    steps = [
        Step("mail__nope", {}, expect_error_code="KS_TOOL_NOT_FOUND"),
        Step("mail__nope", {}, expect_error_code="KS_DENIED"),
        Step("mail__nope", {}),
        Step("echo__echo", {"payload": "fine"}, expect_error_code="KS_DENIED"),
        Step("echo__fail", {"message": "tool error"}),
    ]

    transcript = await run_script(keystone_app.url, steps, token=fake_idp.token_for("alice"))

    assert [e.ok for e in transcript.entries] == [True, False, False, False, False]
    assert transcript.entries[0].error_code == "KS_TOOL_NOT_FOUND"
    assert transcript.entries[4].error_code is None  # the upstream's own error has no Keystone code
    assert not transcript.ok


@pytest.mark.phase(1)
async def test_the_token_is_sent_as_a_bearer_header() -> None:
    seen: list[str | None] = []

    async def record(request: Request) -> JSONResponse:
        seen.append(request.headers.get("authorization"))
        return JSONResponse({"error": "no"}, status_code=401)

    server = ServerThread(
        Starlette(routes=[Route("/mcp", record, methods=["POST", "GET"])])
    ).start()
    try:
        with pytest.raises(Exception):  # noqa: B017 - the SDK wraps the 401 in a group
            await run_script(f"{server.url}/mcp", [Step()], token="t0ken")
    finally:
        server.stop()

    assert seen
    assert set(seen) == {"Bearer t0ken"}


@pytest.mark.services
@pytest.mark.phase(1)
def test_the_command_line_prints_json_lines_and_the_exit_code_says_pass_or_fail(
    keystone_app: KeystoneApp,
    fake_idp: FakeIdp,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    token = ["--token", fake_idp.token_for("olivia")]
    assert main(["--url", keystone_app.url, "--script", str(DEMO), *token]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["ok"] for line in lines] == [True] * 4
    assert lines[1]["tool"] == "bank__get_balance"

    failing = tmp_path / "fail.yaml"
    failing.write_text("- {tool: mail__nope}\n")
    text = ["--format", "text"]
    assert main(["--url", keystone_app.url, "--script", str(failing), *text, *token]) == 1
    assert "FAIL mail__nope" in capsys.readouterr().out


@pytest.mark.services
@pytest.mark.phase(1)
def test_the_command_line_reads_the_token_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, keystone_app: KeystoneApp
) -> None:
    from examples.agents import scripted_agent

    monkeypatch.setenv("KEYSTONE_TOKEN", "from-env")
    captured: dict[str, str | None] = {}

    async def fake_run(
        url: str, steps: object, token: str | None = None
    ) -> scripted_agent.Transcript:
        captured["token"] = token
        return scripted_agent.Transcript()

    monkeypatch.setattr(scripted_agent, "run_script", fake_run)

    scripted_agent.main(["--url", keystone_app.url, "--script", str(DEMO)])

    assert captured["token"] == "from-env"


@pytest.mark.services
@pytest.mark.phase(6)
@pytest.mark.parametrize("approved_after_s", [0.0, 2.5], ids=["in the wait", "after the wait"])
async def test_the_approval_demo_completes_when_an_approver_says_yes(
    keystone_app: KeystoneApp,
    demo_upstreams: DemoUpstreams,
    fake_idp: FakeIdp,
    approver: Approver,
    approved_after_s: float,
) -> None:
    """The app holds a call for a second. An approval inside that time completes the call; one
    after it is waited for by the agent itself, with keystone__await_approval."""

    async def approve() -> None:
        await anyio.sleep(approved_after_s)
        await approver.approve("fine")

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(approve)
        transcript = await run_script(
            keystone_app.url,
            load_steps(SCRIPTS / "approval_demo.yaml"),
            token=fake_idp.token_for("olivia"),
        )

    assert transcript.ok, transcript.text()
    transfer, second = transcript.calls
    assert transfer.tool == "bank__transfer" and "completed" in transfer.text
    assert (transfer.awaited is not None) == (approved_after_s > 1)
    # The second step has nothing left to wait for.
    assert second.tool == "keystone__await_approval" and "nothing to wait for" in second.text
    assert [t["amount"] for t in demo_upstreams.state("bank")["transfers"]] == [900.0]  # type: ignore[attr-defined]


@pytest.mark.services
@pytest.mark.phase(6)
async def test_the_reject_script_passes_only_on_a_rejection_with_the_note(
    keystone_app: KeystoneApp,
    demo_upstreams: DemoUpstreams,
    fake_idp: FakeIdp,
    approver: Approver,
) -> None:
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(approver.reject, "not this quarter")
        transcript = await run_script(
            keystone_app.url,
            load_steps(SCRIPTS / "approval_reject.yaml"),
            token=fake_idp.token_for("olivia"),
        )

    assert transcript.ok, transcript.text()
    [transfer] = transcript.calls
    assert transfer.error_code == "KS_APPROVAL_REJECTED" and "not this quarter" in transfer.text
    assert demo_upstreams.state("bank")["transfers"] == []


@pytest.mark.services
@pytest.mark.phase(6)
async def test_the_pending_script_stops_at_pending_and_waits_only_when_it_asks(
    keystone_app: KeystoneApp,
    demo_upstreams: DemoUpstreams,
    fake_idp: FakeIdp,
    approver: Approver,
) -> None:
    async def approve_late() -> None:
        await anyio.sleep(2.5)  # after the first step has been told it is pending
        await approver.approve("late but fine")

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(approve_late)
        transcript = await run_script(
            keystone_app.url,
            load_steps(SCRIPTS / "approval_pending.yaml"),
            token=fake_idp.token_for("olivia"),
        )

    assert transcript.ok, transcript.text()
    pending, awaited = transcript.calls
    assert pending.error_code == "KS_APPROVAL_PENDING" and pending.awaited is None
    assert awaited.tool == "keystone__await_approval" and "completed" in awaited.text
    # The step waited for the request it was told about.
    assert awaited.arguments["approval_id"] == pending.content[0]["_meta"]["keystone/approval_id"]
    assert [t["amount"] for t in demo_upstreams.state("bank")["transfers"]] == [600.0]  # type: ignore[attr-defined]
