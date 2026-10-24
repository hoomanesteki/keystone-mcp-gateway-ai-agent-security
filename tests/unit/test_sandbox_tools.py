"""KS-802 without Docker: what the sandbox upstream lists, how it turns a call into a run, and what
it says back."""

import json
from collections.abc import Sequence
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from keystone.core.errors import Code, Reject
from keystone.core.types import Risk, ToolTag
from keystone.defense.description_check import Screener
from keystone.gateway.upstreams import UpstreamTool
from keystone.registry.config import ToolOverride
from keystone.sandbox.builtin_upstream import (
    CALL_ID,
    RUN_PYTHON,
    RUN_SHELL,
    SANDBOX_ID,
    SandboxUpstreamClient,
    describe_result,
    sandbox_defaults,
    sandbox_tools,
    with_sandbox_defaults,
)
from keystone.sandbox.runner import (
    MAX_OUTPUT_BYTES,
    MEMORY,
    TMPFS,
    SandboxError,
    SandboxResult,
    SandboxUnavailable,
)
from keystone.settings import SandboxSettings, Settings

pytestmark = pytest.mark.phase(8)

IMAGE = "keystone-sandbox-python:test"


def result(**changes: Any) -> SandboxResult:
    base: dict[str, Any] = {
        "stdout": "4\n",
        "stderr": "",
        "exit_code": 0,
        "timed_out": False,
        "truncated": False,
        "duration_ms": 12.5,
    }
    return SandboxResult(**{**base, **changes})


class FakeRunner:
    """Stands in for SandboxRunner: keeps what it was asked and answers as told."""

    def __init__(self, answer: SandboxResult | Exception | None = None) -> None:
        self.answer = answer or result()
        self.calls: list[dict[str, Any]] = []
        self.trouble: str | None = None

    async def run(
        self,
        image: str,
        cmd: Sequence[str],
        stdin: str | bytes | None = None,
        timeout_s: float = 30.0,
        *,
        call_id: str | None = None,
    ) -> SandboxResult:
        self.calls.append(
            {
                "image": image,
                "cmd": list(cmd),
                "stdin": stdin,
                "timeout_s": timeout_s,
                "id": call_id,
            }
        )
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer

    async def problem(self, image: str) -> str | None:
        return self.trouble


def client(runner: FakeRunner | None = None, *, timeout_s: float = 30.0) -> SandboxUpstreamClient:
    return SandboxUpstreamClient(runner or FakeRunner(), image=IMAGE, timeout_s=timeout_s)  # type: ignore[arg-type]


def text_of(tool_result: Any) -> dict[str, Any]:
    [block] = tool_result.content
    assert block["type"] == "text"
    found: dict[str, Any] = json.loads(block["text"])
    return found


async def test_the_upstream_lists_run_python_and_run_shell() -> None:
    listed = await client().list_tools()

    assert [t.name for t in listed] == [RUN_PYTHON, RUN_SHELL] == ["run_python", "run_shell"]
    assert SANDBOX_ID == "sandbox"
    assert all(isinstance(t, UpstreamTool) for t in listed)


async def test_every_schema_is_valid_and_takes_the_planned_arguments() -> None:
    python, shell = await client().list_tools()

    for tool in (python, shell):
        Draft202012Validator.check_schema(tool.input_schema)
        assert tool.input_schema["additionalProperties"] is False
    assert python.input_schema["required"] == ["code"]
    assert set(python.input_schema["properties"]) == {"code", "stdin"}
    assert shell.input_schema["required"] == ["command"]
    assert set(shell.input_schema["properties"]) == {"command"}
    validator = Draft202012Validator(python.input_schema)
    assert validator.is_valid({"code": "print(1)"})
    assert validator.is_valid({"code": "print(1)", "stdin": "x"})
    assert not validator.is_valid({})
    assert not validator.is_valid({"code": ""})
    assert not validator.is_valid({"code": "x", "extra": 1})
    assert not validator.is_valid({"code": 7})
    # A NUL would end the argument where the kernel reads it, and cut the code short unseen.
    assert not validator.is_valid({"code": "print(1)\x00"})
    assert Draft202012Validator(shell.input_schema).is_valid({"command": "ls\n-a"})
    assert not Draft202012Validator(shell.input_schema).is_valid({"command": "ls\x00"})


def test_the_descriptions_pass_the_screening_that_holds_a_new_tool() -> None:
    screener = Screener()
    for tool in sandbox_tools():
        screening = screener.screen(tool.description, tool.input_schema)

        assert not screening.flagged, (tool.name, screening.hits)


def test_the_descriptions_say_what_the_limits_are() -> None:
    python, shell = sandbox_tools()
    # The text and the container say the same: change one and this test names the other.
    assert (MEMORY, MAX_OUTPUT_BYTES) == ("512m", 64 * 1024)
    assert set(TMPFS.values()) == {"size=64m,noexec", "size=64m"}

    for tool in (python, shell):
        text = tool.description.lower()
        assert "no network" in text
        assert "512 mb" in text
        assert "64 kb" in text
    assert "numpy" in python.description and "pandas" in python.description


def test_the_definitions_do_not_change_between_calls() -> None:
    # They are pinned by hash: a description that differs between two builds quarantines the tool.
    assert sandbox_tools() == sandbox_tools()


def test_the_tools_are_high_risk_with_the_code_exec_tag_unless_the_config_says_otherwise() -> None:
    defaults = sandbox_defaults(SandboxSettings(timeout_s=30))

    for name in (RUN_PYTHON, RUN_SHELL):
        assert defaults[name].risk is Risk.HIGH
        assert defaults[name].tags == [ToolTag.CODE_EXEC]
        # Ten seconds longer than a run, so that a run out of time is a result.
        assert defaults[name].timeout_s == 40


def test_a_tool_setting_in_the_config_changes_only_what_it_names() -> None:
    config = Settings(
        upstreams=[
            {  # type: ignore[list-item]
                "id": "sandbox",
                "tenant": "acme",
                "transport": "builtin",
                "tools": {"run_python": {"cost_per_call_usd": 0.002}},
            }
        ]
    )

    merged = with_sandbox_defaults(config)

    python = merged["sandbox"]["run_python"]
    assert (python.risk, python.tags, python.cost_per_call_usd) == (
        Risk.HIGH,
        [ToolTag.CODE_EXEC],
        0.002,
    )
    assert merged["sandbox"]["run_shell"].risk is Risk.HIGH


def test_a_disabled_sandbox_adds_no_defaults() -> None:
    off = Settings(sandbox_enabled=False)

    assert "sandbox" not in with_sandbox_defaults(off)


def test_an_override_for_another_upstream_is_left_alone() -> None:
    config = Settings(
        upstreams=[
            {"id": "mail", "tenant": "acme", "url": "http://m/mcp", "tools": {"x": {"risk": "low"}}}  # type: ignore[list-item]
        ]
    )

    merged = with_sandbox_defaults(config)

    assert merged["mail"]["x"] == ToolOverride(risk=Risk.LOW)


async def test_run_python_runs_the_code_with_python_and_gives_stdin_to_the_program() -> None:
    runner = FakeRunner()

    await client(runner).call_tool(RUN_PYTHON, {"code": "print(2+2)", "stdin": "in"}, 40)

    [call] = runner.calls
    assert call["image"] == IMAGE
    assert call["cmd"] == ["python", "-c", "print(2+2)"]
    assert call["stdin"] == "in"


async def test_run_shell_runs_the_command_with_sh_c() -> None:
    runner = FakeRunner()

    await client(runner).call_tool(RUN_SHELL, {"command": "ls /"}, 40)

    [call] = runner.calls
    assert call["cmd"] == ["sh", "-c", "ls /"]
    assert call["stdin"] in (None, "")


async def test_the_result_is_one_text_block_with_the_five_facts() -> None:
    answer = result(stdout="a\n", stderr="b\n", exit_code=0, timed_out=False, truncated=False)
    tool_result = await client(FakeRunner(answer)).call_tool(RUN_PYTHON, {"code": "x"}, 40)

    assert len(tool_result.content) == 1
    assert text_of(tool_result) == {
        "exit_code": 0,
        "stdout": "a\n",
        "stderr": "b\n",
        "timed_out": False,
        "truncated": False,
    }
    assert tool_result.is_error is False
    assert tool_result.structured_content is None


async def test_a_program_that_failed_is_an_error_result_the_agent_can_read() -> None:
    failed = await client(FakeRunner(result(exit_code=1, stderr="Traceback"))).call_tool(
        RUN_PYTHON, {"code": "1/0"}, 40
    )
    timed_out = await client(FakeRunner(result(exit_code=137, timed_out=True))).call_tool(
        RUN_PYTHON, {"code": "while 1: pass"}, 40
    )

    assert failed.is_error and text_of(failed)["exit_code"] == 1
    assert timed_out.is_error and text_of(timed_out)["timed_out"] is True


async def test_the_run_limit_is_the_setting_and_stays_inside_the_tools_own_timeout() -> None:
    runner = FakeRunner()

    await client(runner, timeout_s=30).call_tool(RUN_PYTHON, {"code": "x"}, 40)
    await client(runner, timeout_s=30).call_tool(RUN_PYTHON, {"code": "x"}, 10)
    await client(runner, timeout_s=30).call_tool(RUN_PYTHON, {"code": "x"}, 1.5)

    assert [c["timeout_s"] for c in runner.calls] == [30, 8, 1]


async def test_a_sandbox_that_cannot_run_is_an_upstream_error_that_names_nothing() -> None:
    runner = FakeRunner(SandboxUnavailable("the image keystone-sandbox-python:dev is not built"))

    with pytest.raises(Reject) as raised:
        await client(runner).call_tool(RUN_PYTHON, {"code": "x"}, 40)

    assert raised.value.code is Code.UPSTREAM_ERROR
    assert "image" not in raised.value.message and "docker" not in raised.value.message.lower()


async def test_a_run_that_broke_is_an_upstream_error_too() -> None:
    runner = FakeRunner(SandboxError("the exit code is unknown (APIError)"))

    with pytest.raises(Reject) as raised:
        await client(runner).call_tool(RUN_SHELL, {"command": "x"}, 40)

    assert raised.value.code is Code.UPSTREAM_ERROR
    assert "APIError" not in raised.value.message


async def test_code_with_a_nul_byte_or_too_large_to_pass_as_an_argument_is_refused() -> None:
    runner = FakeRunner()

    for code in ("print(1)\x00", "x" * 200_000):
        with pytest.raises(Reject) as raised:
            await client(runner).call_tool(RUN_PYTHON, {"code": code}, 40)
        assert raised.value.code is Code.INVALID_ARGUMENTS
    assert runner.calls == []


async def test_a_tool_the_upstream_does_not_have_is_not_found() -> None:
    with pytest.raises(Reject) as raised:
        await client().call_tool("run_ruby", {"code": "x"}, 40)

    assert raised.value.code is Code.TOOL_NOT_FOUND


async def test_the_call_id_of_the_gateway_labels_the_container() -> None:
    runner = FakeRunner()
    token = CALL_ID.set("01CALL")
    try:
        await client(runner).call_tool(RUN_PYTHON, {"code": "x"}, 40)
    finally:
        CALL_ID.reset(token)
    await client(runner).call_tool(RUN_PYTHON, {"code": "x"}, 40)

    assert [c["id"] for c in runner.calls] == ["01CALL", None]


async def test_health_is_what_the_runner_says_about_the_daemon_and_the_image() -> None:
    runner = FakeRunner()
    assert await client(runner).health() is True

    runner.trouble = "the Docker daemon cannot be reached"
    assert await client(runner).health() is False


async def test_a_client_made_for_listing_only_cannot_run_anything() -> None:
    # The CLI syncs the registry from a process that never runs code.
    listing_only = SandboxUpstreamClient(None, image=IMAGE, timeout_s=30)

    assert [t.name for t in await listing_only.list_tools()] == [RUN_PYTHON, RUN_SHELL]
    assert await listing_only.health() is False
    with pytest.raises(Reject) as raised:
        await listing_only.call_tool(RUN_PYTHON, {"code": "x"}, 40)
    assert raised.value.code is Code.UPSTREAM_ERROR


def test_output_that_came_back_cut_says_so_in_the_text() -> None:
    cut = describe_result(result(stdout="x" * MAX_OUTPUT_BYTES, truncated=True))

    assert json.loads(cut.content[0]["text"])["truncated"] is True
