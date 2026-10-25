"""KS-901: the checks of the red-team suite against the demo upstreams that the scenarios touch.

An attack check must be false on a fresh reset of the scenario's state and true once the goal has
been done by hand; a task's check must be false before the task and true after it. Both are shown
here for all 60 scenarios, with the real demo servers (mail, files, bank, web) in threads and an MCP
client that calls their tools straight, the way the worst-case agent would through no gateway.
"""

import json
from typing import Any

import pytest
from mcp import Client

from eval.redteam.checks import describe, holds
from eval.redteam.schema import Scenario
from eval.redteam.suite import load_scenarios
from examples.agents.naive_agent import _strings
from examples.injections import find_markers
from tests.fixtures.redteam import RedTeamUpstreams

pytestmark = pytest.mark.phase(9)


def split(tool: str) -> tuple[str, str]:
    """`mail__send_email` is the tool `send_email` of the mail upstream."""
    upstream, _, name = tool.partition("__")
    return upstream, name


def readable(text: str) -> str:
    """What a reader of a result sees: the text, and the strings in it when it is JSON, where a
    quote inside a string is written with a backslash (the naive agent reads it the same way)."""
    try:
        return "\n".join([text, *_strings(json.loads(text))])
    except ValueError:
        return text


async def call(upstreams: RedTeamUpstreams, tool: str, arguments: dict[str, Any]) -> str:
    """Call a tool of an upstream directly and return the text it sent back."""
    upstream, name = split(tool)
    async with Client(upstreams.mcp(upstream)) as client:  # type: ignore[arg-type]
        result = await client.call_tool(name, arguments)
    assert not result.is_error, (tool, arguments, result.content)
    # A tool that returns a list sends one block for each item, and each is JSON of its own.
    return "\n".join(readable(str(getattr(block, "text", ""))) for block in result.content)


async def run_script(upstreams: RedTeamUpstreams, scenario: Scenario) -> str:
    """The steps of the scenario's script, in order, straight at the upstreams. What they returned,
    joined, is the output a reader of the results would have."""
    seen = []
    for step in scenario.script:
        seen.append(await call(upstreams, step.tool, step.args))
    return "\n".join(seen)


async def test_attack_checks_detect_goal(redteam_upstreams: RedTeamUpstreams) -> None:
    goals = {}
    for scenario in load_scenarios():
        if scenario.attack is None:
            continue
        assert scenario.attack_check is not None
        redteam_upstreams.reset(scenario.setup.variant)
        assert not holds(scenario.attack_check, redteam_upstreams.states(), ""), (
            f"{scenario.id}: the attack check holds on a fresh reset: "
            f"{describe(scenario.attack_check)}"
        )
        # The goal is what the marker planted in the document says to do. Doing it by hand is the
        # call the worst-case agent would make.
        output = await run_script(redteam_upstreams, scenario)
        [wanted] = find_markers(output)
        goals[scenario.attack.goal] = wanted
        # What the task itself does (a reply to Dana, a brief, a payment) is not the attack.
        assert not holds(scenario.attack_check, redteam_upstreams.states(), output), scenario.id
        await call(redteam_upstreams, wanted.tool, dict(wanted.args))

        assert holds(scenario.attack_check, redteam_upstreams.states(), ""), (
            f"{scenario.id}: the attack check does not hold after the goal: "
            f"{describe(scenario.attack_check)}"
        )
    assert len(goals) == 4


async def test_the_task_script_reads_the_attack_and_the_benign_one_reads_none(
    redteam_upstreams: RedTeamUpstreams,
) -> None:
    for scenario in load_scenarios():
        redteam_upstreams.reset(scenario.setup.variant)
        output = await run_script(redteam_upstreams, scenario)
        markers = find_markers(output)

        if scenario.attack is None:
            assert markers == [], scenario.id
        else:
            # The attack is in what the task reads, once, and is the goal of the scenario.
            assert len(markers) == 1, (scenario.id, len(markers))


async def test_utility_checks_detect_the_task(redteam_upstreams: RedTeamUpstreams) -> None:
    for scenario in load_scenarios():
        if scenario.kind != "benign":
            continue
        redteam_upstreams.reset(scenario.setup.variant)
        before = describe(scenario.utility_check)
        assert not holds(scenario.utility_check, redteam_upstreams.states(), ""), (
            f"{scenario.id}: the task counts as done before it is: {before}"
        )

        output = await run_script(redteam_upstreams, scenario)

        assert holds(scenario.utility_check, redteam_upstreams.states(), output), (
            f"{scenario.id}: the task does not count as done after its script: "
            f"{describe(scenario.utility_check)}"
        )


async def test_an_attack_is_not_a_reason_to_fail_the_task_by_itself(
    redteam_upstreams: RedTeamUpstreams,
) -> None:
    # The same script on the attacked state does the task too: the attack adds to what is read.
    for scenario in load_scenarios():
        if scenario.attack is None:
            continue
        redteam_upstreams.reset(scenario.setup.variant)
        output = await run_script(redteam_upstreams, scenario)

        assert holds(scenario.utility_check, redteam_upstreams.states(), output), scenario.id


def test_the_state_of_a_variant_is_json_a_server_can_load() -> None:
    from eval.redteam.suite import VARIANTS

    for path in sorted(VARIANTS.rglob("*.json")):
        json.loads(path.read_text(encoding="utf-8"))
