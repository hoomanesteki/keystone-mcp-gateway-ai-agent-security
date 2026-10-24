"""Keystone's output defense as an element of an AgentDojo pipeline (KS-904).

AgentDojo runs an agent on user tasks in simulated environments (a workspace, a bank, a travel
site, a chat) while an attacker plants instructions in what the tools return, and says how often the
agent still did the user's task (utility) and how often it did the attacker's (security). A defense
is an element of the pipeline that sees each tool result before the model does.

This is Keystone's. It sends the text of every tool result to `POST /admin/api/v1/scan`, which runs
the scan and the action that a call through the gateway would get (the rules, the model, the action
for the risk), and gives the model what Keystone says it should see: the result as it came, with a
warning in front, with the hidden characters cut out, or a refusal in its place. The Rule of Two is
not mirrored: AgentDojo's tools carry no tags (it knows nothing of what a tool reads or changes), so
there is nothing for a session to count.

Nothing here imports AgentDojo. The element is built for the base class and the two helpers that
`eval/agentdojo/run.py` takes from the package (`build_element`), so that the part that decides what
the model sees can be tested without the benchmark, which needs a model to run.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx

AGENTDOJO_VERSION = "0.1.35"
SCAN_PATH = "/admin/api/v1/scan"
RISKS = ("low", "medium", "high", "critical")
TIMEOUT_S = 60.0


class ScanError(RuntimeError):
    """Keystone could not scan a text. A benchmark that went on without the defense would report a
    number for something else, so the run stops."""


@dataclass(frozen=True)
class Verdict:
    """What Keystone made of a text."""

    score: float
    label: str
    action: str
    rule_hits: tuple[str, ...]
    model: str | None
    # What the model should be given: the text as it came for `pass`, otherwise Keystone's own
    # blocks joined (the warning and the delimiters of `annotate`, the refusal of `block`).
    text: str
    is_error: bool

    @property
    def changed(self) -> bool:
        return self.action != "pass"


def verdict_from(answer: Mapping[str, Any], original: str) -> Verdict:
    """Read the answer of the scan route. A text that was not flagged is returned as it came, byte
    for byte, whatever the blocks say."""
    scan = answer["scan"]
    action = str(scan["action"])
    blocks = [b for b in answer.get("content", []) if b.get("type") == "text"]
    text = original if action == "pass" else "\n".join(str(b.get("text", "")) for b in blocks)
    return Verdict(
        score=float(scan["score"]),
        label=str(scan["label"]),
        action=action,
        rule_hits=tuple(scan.get("rule_hits") or ()),
        model=scan.get("model"),
        text=text,
        is_error=bool(answer.get("is_error")),
    )


class KeystoneScanner:
    """Asks a running Keystone to scan a text. `token` is an admin's access token, or a function
    that gives one (a token of the local realm lives five minutes, so a run asks again when
    Keystone answers 401)."""

    def __init__(
        self,
        base_url: str,
        token: str | Callable[[], str],
        *,
        risk: str = "medium",
        client: httpx.Client | None = None,
    ) -> None:
        if risk not in RISKS:
            raise ValueError(f"risk must be one of {', '.join(RISKS)}")
        self._url = base_url.rstrip("/") + SCAN_PATH
        self._token = token
        self._risk = risk
        self._client = client or httpx.Client(timeout=TIMEOUT_S)
        self._bearer: str | None = None

    def _headers(self, fresh: bool = False) -> dict[str, str]:
        if self._bearer is None or fresh:
            self._bearer = self._token() if callable(self._token) else self._token
        return {"Authorization": f"Bearer {self._bearer}"}

    def scan(self, text: str) -> Verdict:
        body = {"text": text, "risk": self._risk}
        try:
            answer = self._client.post(self._url, json=body, headers=self._headers())
            if answer.status_code == 401 and callable(self._token):
                answer = self._client.post(self._url, json=body, headers=self._headers(fresh=True))
        except httpx.HTTPError as error:
            raise ScanError(f"Keystone did not answer: {type(error).__name__}") from None
        if answer.status_code != 200:
            raise ScanError(
                f"Keystone answered {answer.status_code} to the scan: {answer.text[:200]}"
            )
        return verdict_from(answer.json(), text)


@dataclass
class Counts:
    """What the element did, for the report of a run."""

    scanned: int = 0
    by_action: dict[str, int] = field(default_factory=dict)
    scores: list[float] = field(default_factory=list)

    def add(self, verdict: Verdict) -> None:
        self.scanned += 1
        self.by_action[verdict.action] = self.by_action.get(verdict.action, 0) + 1
        self.scores.append(verdict.score)


def replace_tool_results(
    messages: Sequence[Any],
    scan: Callable[[str], Verdict],
    get_text: Callable[[Any], str],
    make_block: Callable[[str], Any],
    counts: Counts,
) -> None:
    """Scan the tool results at the end of a conversation and replace, in place, the ones Keystone
    changed. A message with no text in it is not sent. Only the results that came in the last turn
    are looked at: an earlier one was scanned when it came."""
    first = len(messages)
    while first > 0 and messages[first - 1]["role"] == "tool":
        first -= 1
    for message in messages[first:]:
        text = get_text(message["content"] or [])
        if text.strip():
            verdict = scan(text)
            counts.add(verdict)
            if verdict.changed:
                message["content"] = [make_block(verdict.text)]


def add_to_pipeline(
    pipeline: Any, element: Any, loop_type: type[Any], executor_type: type[Any]
) -> None:
    """Put the element in the tools loop of an AgentDojo pipeline, right after the tools have run
    and before the model is asked again: the place of AgentDojo's own detectors. `loop_type` and
    `executor_type` are `ToolsExecutionLoop` and `ToolsExecutor`. A pipeline with no such loop, or
    with more than one, is not one this knows how to put a defense in, and the run stops."""
    loops = [step for step in pipeline.elements if isinstance(step, loop_type)]
    if len(loops) != 1:
        raise ValueError(f"expected one tools loop in the pipeline, found {len(loops)}")
    steps = list(loops[0].elements)
    executors = [i for i, step in enumerate(steps) if isinstance(step, executor_type)]
    if len(executors) != 1:
        raise ValueError(f"expected one tools executor in the tools loop, found {len(executors)}")
    steps.insert(executors[0] + 1, element)
    loops[0].elements = steps


def build_element(
    base: type,
    scanner: KeystoneScanner,
    get_text: Callable[[Any], str],
    make_block: Callable[[str], Any],
) -> Any:
    """The pipeline element, as a subclass of AgentDojo's `BasePipelineElement` (`base`).
    `get_text` and `make_block` are `get_text_content_as_str` and `text_content_block_from_string`
    of `agentdojo.types`. The element keeps its `counts`."""

    class KeystoneDefense(base):  # type: ignore[misc, valid-type]
        name = "keystone"

        def __init__(self) -> None:
            super().__init__()
            self.counts = Counts()

        def query(
            self,
            query: str,
            runtime: Any,
            env: Any = None,
            messages: Sequence[Any] = (),
            extra_args: dict[str, Any] | None = None,
        ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
            replace_tool_results(messages, scanner.scan, get_text, make_block, self.counts)
            return query, runtime, env, messages, extra_args or {}

    return KeystoneDefense()
