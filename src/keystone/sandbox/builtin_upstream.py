"""The `sandbox` upstream: running code as a governed tool (KS-802, ADR-0012).

It is an upstream in the same sense as the others. It has a row in `upstreams` (transport
`builtin`), its two tools are synced into the registry and pinned by hash like any tool, and a call
to one goes through the whole pipeline: the policy, the approval, the output scan and the audit
record. What differs is the end of the line: the client here starts a container where the others
open a connection.

- `run_python(code, stdin)` runs `python -c code`, with the input on standard input
- `run_shell(command)` runs `sh -c command`

Both are high risk with the tag `code_exec`, so by the default access policy the operators group
may call them and nobody else may (a user in `support` is denied, and does not see the tools). A
tenant that wants other rules writes them in Cedar like for any tool, or sets `risk` and `tags` for
the tools in the config. The result is one text block of JSON with the exit code, both outputs and
the flags for a run that timed out and one that was cut at 64 KB, and an error result when the
program failed or timed out. What a program prints is the output of a tool like any other: it goes
through the scanner, and a script that prints an instruction taints the session like a web page
that holds one.

The descriptions are part of what is pinned. A new release that words one differently holds the
tool until a person has read the change, as it does for any upstream.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

import structlog

from keystone.core.errors import Code, Reject
from keystone.core.types import Risk, ToolResult, ToolTag
from keystone.gateway.upstreams import CALL_ID, UpstreamClient, UpstreamTool
from keystone.registry.config import ToolOverride, tool_overrides
from keystone.sandbox.runner import (
    SandboxError,
    SandboxResult,
    SandboxRunner,
    SandboxUnavailable,
)
from keystone.settings import SandboxSettings, Settings

__all__ = [
    "CALL_ID",
    "RUN_PYTHON",
    "RUN_SHELL",
    "SANDBOX_ID",
    "SandboxUpstreamClient",
    "builtin_clients",
    "describe_result",
    "sandbox_defaults",
    "sandbox_registered",
    "sandbox_tools",
    "with_sandbox_defaults",
]

log = structlog.get_logger()

SANDBOX_ID = "sandbox"
RUN_PYTHON = "run_python"
RUN_SHELL = "run_shell"

# A NUL ends a string where an argument reaches the kernel, so code that holds one would be cut
# short without a word. The schema refuses it, and the call stops before it is dispatched.
NO_NUL = r"^[^\x00]*$"
# An argument of a program reaches the kernel as one string of at most 128 KiB (MAX_ARG_STRLEN), so
# code longer than this cannot be passed with `python -c`. The schema says 100,000 characters,
# which is more than this in some alphabets, so the bytes are counted too.
MAX_CODE_BYTES = 120_000
MAX_CODE_CHARS = 100_000
MAX_STDIN_CHARS = 1_000_000
# How much longer than a run the tool's own timeout is, and how much of the tool's timeout a run
# leaves for the call around it. A run that ends on its own limit is a result the agent can read;
# one cut off by the timeout of the call would be a failed call.
RUN_MARGIN_S = 2.0
TOOL_MARGIN_S = 10.0

# What the agent is told. The cause is in the log, and it can hold a path or an address.
NOT_AVAILABLE = "the sandbox is not available"
NOT_RUN = "the sandbox could not run the code"

# The numbers are those of the container (runner.py); a test holds the two together. A description
# that changes holds the tool until a person has read it, which is what a change to the limits
# deserves.
LIMITS = (
    "The container has no network, a read-only filesystem except /tmp and /workspace (64 MB each, "
    "erased when the call ends), 512 MB of memory and one CPU. Output is cut at 64 KB for each of "
    "stdout and stderr, and a run that takes longer than the time limit is stopped."
)
RUN_PYTHON_DESCRIPTION = (
    "Run Python 3.12 code in a fresh, isolated container and return its exit code, stdout and "
    f"stderr. numpy and pandas are installed. {LIMITS} Give the program input in stdin."
)
RUN_SHELL_DESCRIPTION = (
    "Run a shell command (sh -c) in a fresh, isolated container, the same one run_python uses, and "
    f"return its exit code, stdout and stderr. {LIMITS}"
)


def sandbox_tools() -> list[UpstreamTool]:
    return [
        UpstreamTool(
            name=RUN_PYTHON,
            description=RUN_PYTHON_DESCRIPTION,
            input_schema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_CODE_CHARS,
                        "pattern": NO_NUL,
                        "description": "The Python source to run.",
                    },
                    "stdin": {
                        "type": "string",
                        "maxLength": MAX_STDIN_CHARS,
                        "default": "",
                        "description": "Text for the program's standard input.",
                    },
                },
                "required": ["code"],
                "additionalProperties": False,
            },
        ),
        UpstreamTool(
            name=RUN_SHELL,
            description=RUN_SHELL_DESCRIPTION,
            input_schema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_CODE_CHARS,
                        "pattern": NO_NUL,
                        "description": "The command line, run with sh -c.",
                    },
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        ),
    ]


def describe_result(result: SandboxResult) -> ToolResult:
    """One text block with the five facts. A program that failed or ran out of time is an error
    result, so that an agent framework treats the step as failed, and the block still says why."""
    facts = {
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "truncated": result.truncated,
    }
    # Not ASCII-escaped: the scanner reads this text, and an invisible character written as
    # ​ is no longer one.
    text = json.dumps(facts, ensure_ascii=False)
    failed = result.exit_code != 0 or result.timed_out
    return ToolResult(content=[{"type": "text", "text": text}], is_error=failed)


class Runs(Protocol):
    """What the client needs of the runner. SandboxRunner is one; a test has another."""

    async def run(
        self,
        image: str,
        cmd: Sequence[str],
        stdin: str | bytes | None = None,
        timeout_s: float = 30.0,
        *,
        call_id: str | None = None,
    ) -> SandboxResult: ...

    async def problem(self, image: str) -> str | None: ...


def _text(arguments: Mapping[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value:
        raise Reject(Code.INVALID_ARGUMENTS, f"{key} must be a non-empty string")
    if "\x00" in value:
        raise Reject(Code.INVALID_ARGUMENTS, f"{key} cannot hold a NUL character")
    if len(value.encode()) > MAX_CODE_BYTES:
        raise Reject(Code.INVALID_ARGUMENTS, f"{key} is longer than {MAX_CODE_BYTES} bytes")
    return value


class SandboxUpstreamClient:
    """The client of the `sandbox` upstream (the `UpstreamClient` protocol of the pool).

    `runner` is None in a process that lists the tools and runs nothing (the CLI syncs the registry
    from one): it lists, says it is not healthy, and refuses a call.
    """

    def __init__(self, runner: Runs | None, *, image: str, timeout_s: float) -> None:
        self._runner = runner
        self._image = image
        self._timeout_s = timeout_s

    async def list_tools(self) -> list[UpstreamTool]:
        return sandbox_tools()

    async def call_tool(
        self,
        name: str,
        args: dict[str, Any],
        timeout_s: float,
        meta: Mapping[str, str] | None = None,
    ) -> ToolResult:
        if name == RUN_PYTHON:
            command = ["python", "-c", _text(args, "code")]
            stdin = args.get("stdin") or None
            if stdin is not None and not isinstance(stdin, str):
                raise Reject(Code.INVALID_ARGUMENTS, "stdin must be a string")
        elif name == RUN_SHELL:
            command, stdin = ["sh", "-c", _text(args, "command")], None
        else:
            raise Reject(Code.TOOL_NOT_FOUND, f"the sandbox has no tool named {name!r}")
        if self._runner is None:
            raise Reject(Code.UPSTREAM_ERROR, NOT_AVAILABLE)
        # The run ends on its own limit before the call's does, whichever is the shorter.
        limit = min(self._timeout_s, max(1.0, timeout_s - RUN_MARGIN_S))
        try:
            result = await self._runner.run(
                self._image, command, stdin, limit, call_id=CALL_ID.get()
            )
        except SandboxUnavailable as error:
            log.error("sandbox_unavailable", cause=str(error))
            raise Reject(Code.UPSTREAM_ERROR, NOT_AVAILABLE) from None
        except SandboxError as error:
            log.error("sandbox_run_failed", cause=str(error))
            raise Reject(Code.UPSTREAM_ERROR, NOT_RUN) from None
        return describe_result(result)

    async def health(self) -> bool:
        if self._runner is None:
            return False
        problem = await self._runner.problem(self._image)
        if problem is not None:
            log.warning("sandbox_not_healthy", cause=problem)
        return problem is None

    async def aclose(self) -> None:
        return None


def sandbox_registered(settings: Settings) -> bool:
    """Whether this process serves the `sandbox` upstream: it is on (`KEYSTONE_SANDBOX_ENABLED`)
    and the config lists it. A deployment with no Docker socket turns it off, and the upstream is
    then neither registered nor listed."""
    return settings.sandbox.enabled and any(
        u.transport == "builtin" and u.id == SANDBOX_ID for u in settings.upstreams
    )


def sandbox_defaults(sandbox: SandboxSettings) -> dict[str, ToolOverride]:
    """How the two tools are classified when the config says nothing: high risk, tagged
    `code_exec`, and a timeout ten seconds longer than a run."""
    return {
        name: ToolOverride(
            risk=Risk.HIGH,
            tags=[ToolTag.CODE_EXEC],
            timeout_s=sandbox.timeout_s + TOOL_MARGIN_S,
        )
        for name in (RUN_PYTHON, RUN_SHELL)
    }


def with_sandbox_defaults(settings: Settings) -> dict[str, dict[str, ToolOverride]]:
    """The per-tool settings of the config, with the sandbox's defaults under them. What the config
    sets for a tool of the sandbox (a price, say) replaces the default for that field only."""
    overrides = tool_overrides(settings.upstreams)
    if not sandbox_registered(settings):
        return overrides
    configured = overrides.get(SANDBOX_ID, {})
    merged: dict[str, ToolOverride] = {}
    for name, default in sandbox_defaults(settings.sandbox).items():
        given = configured.get(name)
        changes = given.model_dump(exclude_unset=True) if given is not None else {}
        merged[name] = default.model_copy(update=changes)
    # A setting for a tool the sandbox does not have is left for the sync to warn about.
    merged.update({name: o for name, o in configured.items() if name not in merged})
    return {**overrides, SANDBOX_ID: merged}


def builtin_clients(
    settings: Settings, runner: SandboxRunner | None
) -> dict[str, Callable[[], UpstreamClient]]:
    """The clients for the upstreams that Keystone runs itself, by upstream id. Empty when the
    sandbox is off, so that the pool does not serve an upstream the settings turned off."""
    if not sandbox_registered(settings):
        return {}

    def make() -> UpstreamClient:
        return SandboxUpstreamClient(
            runner, image=settings.sandbox.image, timeout_s=settings.sandbox.timeout_s
        )

    return {SANDBOX_ID: make}
