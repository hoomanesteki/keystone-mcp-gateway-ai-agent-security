from pathlib import Path

import pytest

from examples.agents.scripted_agent import (
    Entry,
    ScriptError,
    Step,
    Transcript,
    load_steps,
)

ROOT = Path(__file__).resolve().parents[2]


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "script.yaml"
    path.write_text(text)
    return path


@pytest.mark.phase(1)
def test_the_phase_1_demo_script_has_four_steps_in_the_planned_order() -> None:
    steps = load_steps(ROOT / "examples" / "agents" / "scripts" / "demo_p1.yaml")

    assert [s.tool for s in steps] == [
        None,
        "bank__get_balance",
        "mail__send_email",
        "mail__read_email",
    ]
    assert steps[2].args["to"] == "colleague@acme.test"
    text = (ROOT / "examples" / "agents" / "scripts" / "demo_p1.yaml").read_text()
    assert "Rule of Two" in text  # the comment that says why the order matters


@pytest.mark.phase(1)
def test_steps_load_with_args_and_an_expected_error(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        "steps:\n"
        "  - list_tools: true\n"
        "  - {tool: echo__echo, args: {payload: hi}}\n"
        "  - {tool: bank__transfer, expect_error_code: KS_DENIED}\n",
    )

    assert load_steps(path) == [
        Step(),
        Step("echo__echo", {"payload": "hi"}),
        Step("bank__transfer", {}, "KS_DENIED"),
    ]


@pytest.mark.phase(1)
def test_a_bare_list_is_a_script_too(tmp_path: Path) -> None:
    assert load_steps(write(tmp_path, "- {tool: echo__echo}\n")) == [Step("echo__echo")]


@pytest.mark.phase(1)
@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "expected a list"),
        ("steps: []\n", "expected a list"),
        ("- hello\n", "not a mapping"),
        ("- {args: {a: 1}}\n", "needs a 'tool'"),
        ("- {tool: x, arg: {}}\n", "unknown keys"),
        ("- {tool: x, args: [1]}\n", "must be a mapping"),
    ],
)
def test_a_bad_script_is_refused(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(ScriptError, match=message):
        load_steps(write(tmp_path, text))


@pytest.mark.phase(1)
def test_the_transcript_prints_one_json_object_per_step_and_a_readable_form() -> None:
    transcript = Transcript(
        [
            Entry(1, "list_tools", ok=True, tools=["a__x", "b__y"]),
            Entry(
                2,
                "call_tool",
                ok=True,
                tool="bank__get_balance",
                arguments={"account": "CHK-001"},
                call_id="01JCALL",
                text="balance 4825.5",
                content=[{"type": "text", "text": "x"}],
            ),
            Entry(
                3,
                "call_tool",
                ok=False,
                tool="mail__nope",
                is_error=True,
                error_code="KS_X",
                text="no",
            ),
        ]
    )

    lines = transcript.json_lines()

    assert len(lines) == 3
    assert '"call_id": "01JCALL"' in lines[1]
    assert "content" not in lines[1]
    text = transcript.text()
    assert "2. ok   bank__get_balance" in text
    assert "call_id 01JCALL" in text
    assert "3. FAIL mail__nope" in text
    assert "KS_X: no" in text
    assert transcript.ok is False
    assert len(transcript.calls) == 2
