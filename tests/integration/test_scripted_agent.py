import json
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from examples.agents.scripted_agent import Step, load_steps, main, run_script
from tests.fixtures.keystone import KeystoneApp
from tests.fixtures.servers import ServerThread
from tests.fixtures.upstreams import DemoUpstreams

DEMO = Path(__file__).resolve().parents[2] / "examples" / "agents" / "scripts" / "demo_p1.yaml"


@pytest.mark.phase(1)
async def test_the_demo_script_runs_through_keystone(
    keystone_app: KeystoneApp, demo_upstreams: DemoUpstreams
) -> None:
    transcript = await run_script(keystone_app.url, load_steps(DEMO))

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


@pytest.mark.phase(1)
async def test_a_refusal_matches_expect_error_code_and_anything_else_fails(
    keystone_app: KeystoneApp,
) -> None:
    steps = [
        Step("mail__nope", {}, expect_error_code="KS_TOOL_NOT_FOUND"),
        Step("mail__nope", {}, expect_error_code="KS_DENIED"),
        Step("mail__nope", {}),
        Step("echo__echo", {"payload": "fine"}, expect_error_code="KS_DENIED"),
        Step("echo__fail", {"message": "tool error"}),
    ]

    transcript = await run_script(keystone_app.url, steps)

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


@pytest.mark.phase(1)
def test_the_command_line_prints_json_lines_and_the_exit_code_says_pass_or_fail(
    keystone_app: KeystoneApp, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert main(["--url", keystone_app.url, "--script", str(DEMO)]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["ok"] for line in lines] == [True] * 4
    assert lines[1]["tool"] == "bank__get_balance"

    failing = tmp_path / "fail.yaml"
    failing.write_text("- {tool: mail__nope}\n")
    assert main(["--url", keystone_app.url, "--script", str(failing), "--format", "text"]) == 1
    assert "FAIL mail__nope" in capsys.readouterr().out


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
