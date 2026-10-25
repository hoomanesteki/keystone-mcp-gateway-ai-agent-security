"""The scanner: read what a tool result says, and judge whether it is an instruction (KS-701).

`extract` turns a result into the text a reader of it would see. `CompositeScanner` scores that
text with the rules (`rules.py`) and, when there is one, a classifier (`classifier.py`), and gives
it a label. `OutputScanner` is what the pipeline will call (KS-704): it scans a tool result and
applies the action for the tool's risk (`actions.py`), and it cannot raise. The scanner itself
changes nothing it is given.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import anyio
import structlog

from keystone.core.types import ScanResult, ToolRef, ToolResult
from keystone.defense import actions
from keystone.defense.classifier import Classifier, ClassifierBusy
from keystone.defense.rules import Rule, analyze, combine, default_rules, prepare, reveal_tags
from keystone.settings import ScannerSettings, ScannerThresholds

log = structlog.get_logger()

Label = Literal["benign", "suspicious", "injection"]

# Text that is JSON is read as the strings in it. Beyond this size it is read as it is.
MAX_JSON_CHARS = 5_000_000
# What `model` says when the classifier was asked and gave no answer in time, and when it raised.
TIMEOUT = "timeout"
FAILED = "error"
BUSY = "busy"
# What it says when the rules had already flagged the text and the model was not asked (KS-792).
SKIPPED = "skipped"


@dataclass(frozen=True)
class Extracted:
    text: str
    # Image blocks cannot be read, so they are left out and counted. Pictures that carry
    # instructions are not seen (multimodal injection is on the list after v1).
    images_skipped: int = 0


def _strings(value: Any) -> Iterator[str]:
    """Every string in a JSON value, keys included, in order. It uses a stack, because a value
    nested a thousand deep is a way to crash a function that calls itself."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            for key, child in reversed(list(item.items())):
                stack.append(child)
                stack.append(key)
        elif isinstance(item, list):
            stack.extend(reversed(item))


def _view(text: str) -> tuple[str, Any]:
    """What a reader sees of a text block. A tool that returns an object sends it as JSON text,
    where a line break or a quote inside a string is written with a backslash. A reader undoes
    that, so the scanner does: a phrase wrapped over two lines is still a phrase. The parsed value
    comes back too, or None when the text is not JSON."""
    if text.lstrip()[:1] in ("{", "[") and len(text) <= MAX_JSON_CHARS:
        try:
            parsed = json.loads(text)
        except (ValueError, RecursionError):
            return text, None
        return "\n".join(_strings(parsed)), parsed
    return text, None


def extract(result: ToolResult) -> Extracted:
    """The text of a result: its text blocks, the text of embedded resources, the name and
    description of resource links, and structured content that the text blocks do not already
    say. Blocks are joined with a line break."""
    parts: list[str] = []
    parsed_blocks: list[Any] = []
    images = 0
    for block in result.content:
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        if kind == "image":
            images += 1
        elif kind == "resource":
            resource = block.get("resource")
            text = resource.get("text") if isinstance(resource, dict) else None
            if isinstance(text, str):
                view, parsed = _view(text)
                parts.append(view)
                if parsed is not None:
                    parsed_blocks.append(parsed)
        elif kind == "resource_link":
            parts.extend(
                value
                for key in ("name", "title", "description")
                if isinstance(value := block.get(key), str)
            )
        else:
            text = block.get("text")
            if isinstance(text, str):
                view, parsed = _view(text)
                parts.append(view)
                if parsed is not None:
                    parsed_blocks.append(parsed)
    structured = result.structured_content
    if structured is not None and structured not in parsed_blocks:
        parts.extend(_strings(structured))
    return Extracted("\n".join(parts), images)


def extract_text(result: ToolResult) -> str:
    return extract(result).text


class ScanDetails(ScanResult):
    """A `ScanResult` that also says what the scan did to the text it was given."""

    # NFKC changed the text the phrase rules read (fullwidth letters, ligatures).
    normalized: bool = False
    # The text was longer than `scanner.max_scan_chars` and only its two ends were read.
    truncated: bool = False
    # The two scores the final one is the higher of. The classifier's is None when there is no
    # classifier or it gave no answer in time.
    rule_score: float = 0.0
    classifier_score: float | None = None


def label_for(score: float, thresholds: ScannerThresholds) -> Label:
    if score >= thresholds.injection:
        return "injection"
    if score >= thresholds.suspicious:
        return "suspicious"
    return "benign"


def rules_first(rules: float, model: float | None, *, floor: float, weight: float) -> float:
    """The score of a text from the score of the rules and the score of the model (KS-792,
    ADR-0011). A text the rules flag, at `floor` or more, keeps their score whatever the model
    says: the model is not asked. For any other text the model adds to the rules' score as a second
    witness that is right `weight` of the time it is sure, `1 - (1 - rules) * (1 - weight * model)`,
    the same way the rules' own hits add up. So the model can raise a score and never lowers one,
    and with a weight under 0.85 it cannot make an `injection` of a text the rules do not flag.
    `model` is None when there is none or it gave no answer."""
    if model is None or rules >= floor:
        return rules
    return 1 - (1 - rules) * (1 - weight * model)


class CompositeScanner:
    """Scores a text with the rules and, when there is one, a classifier. The rules are cheap and
    exact about what they name, and the classifier sees what no pattern names. With
    `scanner.join` set to `rules_first` (the default) a text that the rules flag is judged by them
    alone and the model is not asked (`model` says "skipped"); any other text gets the model's
    score at `model_weight` added to the rules' (`rules_first`). With `max` the final score is the
    higher of the two and the model reads every text, which is what Phase 7 shipped. A classifier
    that does not answer within `classifier_timeout_ms` is left out of that scan, which is then the
    rules alone, and `model` says "timeout". A classifier that raises is left out the same way,
    `model` says "error", and `on_error("classifier")` is called. The rules are not guarded here:
    an exception in them reaches the caller, which is `OutputScanner`."""

    def __init__(
        self,
        rules: Sequence[Rule],
        classifier: Classifier | None = None,
        cfg: ScannerSettings | None = None,
        *,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self._rules = list(rules)
        self._classifier = classifier
        self._cfg = cfg or ScannerSettings()
        self._on_error = on_error

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    async def scan(self, text: str, *, tool: ToolRef) -> ScanResult:
        started = time.perf_counter()
        window, truncated = self._window(text)
        details = self._rules_pass(window, truncated)
        classifier = self._classifier
        if classifier is not None and self._skips_model(details.score):
            details = details.model_copy(update={"model": SKIPPED})
        elif classifier is not None:
            view = prepare(reveal_tags(window))[0]
            answer, model = await self._ask(classifier, view)
            heard = None if answer is None else round(answer, 6)
            # Rounded so that a score meant to sit on a threshold does so, as for the rules.
            score = round(self._join(details.score, heard), 6)
            details = details.model_copy(
                update={
                    "score": score,
                    "label": label_for(score, self._cfg.thresholds),
                    "model": model,
                    "classifier_score": heard,
                }
            )
        return details.model_copy(update={"latency_ms": (time.perf_counter() - started) * 1000})

    def _skips_model(self, rules: float) -> bool:
        """Whether the rules have flagged the text, so that the model is not asked."""
        return self._cfg.join == "rules_first" and rules >= self._cfg.thresholds.suspicious

    def _join(self, rules: float, model: float | None) -> float:
        if self._cfg.join == "max":
            return rules if model is None else max(rules, model)
        return rules_first(
            rules,
            model,
            floor=self._cfg.thresholds.suspicious,
            weight=self._cfg.model_weight,
        )

    def scan_text(self, text: str) -> ScanDetails:
        """The rules alone, without waiting for anything. They are a few milliseconds of Python."""
        started = time.perf_counter()
        window, truncated = self._window(text)
        details = self._rules_pass(window, truncated)
        return details.model_copy(update={"latency_ms": (time.perf_counter() - started) * 1000})

    def _rules_pass(self, window: str, truncated: bool) -> ScanDetails:
        hits, normalized = analyze(window, self._rules)
        # Rounded so that a score meant to sit on a threshold does so (1 - 0.4 * 0.5 is 0.8).
        score = round(combine(hit.weight for hit in hits), 6)
        return ScanDetails(
            score=score,
            label=label_for(score, self._cfg.thresholds),
            rule_hits=[hit.id for hit in hits],
            action="pass",
            model=None,
            normalized=normalized,
            truncated=truncated,
            rule_score=score,
        )

    async def _ask(self, classifier: Classifier, view: str) -> tuple[float | None, str]:
        """The classifier's score and the name for `model`: its own, or "timeout", or "error"."""
        try:
            with anyio.move_on_after(self._cfg.classifier_timeout_ms / 1000):
                answer = await classifier.score(view)
                return (answer, classifier.name) if answer is not None else (None, TIMEOUT)
        except ClassifierBusy:
            return None, BUSY
        except Exception as error:
            # Cancellation is not an Exception, so it goes through. What the model was asked is
            # not logged: it is the content of a tool output.
            log.error(
                "scanner_classifier_failed", classifier=classifier.name, error=type(error).__name__
            )
            log.debug("scanner_classifier_failed_detail", exc_info=True)
            if self._on_error is not None:
                self._on_error("classifier")
            return None, FAILED
        return None, TIMEOUT

    def _window(self, text: str) -> tuple[str, bool]:
        """The text, or its two ends when it is longer than the limit."""
        limit = self._cfg.max_scan_chars
        if len(text) <= limit:
            return text, False
        half = limit // 2
        return f"{text[:half]}\n\n{text[-half:]}", True


def build_scanner(cfg: ScannerSettings, classifier: Classifier | None = None) -> CompositeScanner:
    return CompositeScanner(default_rules(cfg.allowed_domains), classifier, cfg)


@dataclass(frozen=True)
class Inspection:
    """What `OutputScanner.inspect` found and what goes on. `result` is the same object when
    nothing was done to it."""

    result: ToolResult
    scan: ScanResult
    images_skipped: int = 0


class OutputScanner:
    """Scans the result of a tool call and applies the action for the tool's risk. It is what the
    output slot of the pipeline calls (KS-704), and it never raises, because a scanner that can
    crash a call is a scanner people turn off:

    - the rules raise: the output goes on as it is, the scan says `action="error"`, and
      `on_error("rules")` is called. Nothing is flagged because nothing could be judged.
    - the classifier raises or is slow: the rules alone decide (`CompositeScanner`).
    - an action raises on an output that was flagged: the output is withheld, because it was found
      to be suspect and could not be made safe, and `on_error("action")` is called.

    A benign output is returned as the object it came in.
    """

    def __init__(
        self,
        scanner: CompositeScanner,
        cfg: ScannerSettings,
        *,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self._scanner = scanner
        self._cfg = cfg
        self._on_error = on_error

    async def inspect(self, result: ToolResult, tool: ToolRef, call_id: str) -> Inspection:
        try:
            extracted = extract(result)
            scan = await self._scanner.scan(extracted.text, tool=tool)
        except Exception as error:
            log.error("scanner_rules_failed", error=type(error).__name__, call_id=call_id)
            log.debug("scanner_rules_failed_detail", exc_info=True)
            self._report("rules")
            return Inspection(result, ScanResult(score=0.0, label="benign", action="error"))
        if scan.label == "benign":
            return Inspection(result, scan, extracted.images_skipped)
        action: actions.Action = getattr(self._cfg.actions, tool.risk.value)
        try:
            changed = actions.apply(
                action, result, scan, call_id=call_id, rules=self._scanner.rules
            )
        except Exception as error:
            log.error(
                "scanner_action_failed", action=action, error=type(error).__name__, call_id=call_id
            )
            log.debug("scanner_action_failed_detail", exc_info=True)
            self._report("action")
            action = "block"
            changed = actions.block(scan.model_copy(update={"action": action}), call_id)
        return Inspection(
            changed, scan.model_copy(update={"action": action}), extracted.images_skipped
        )

    def _report(self, stage: str) -> None:
        if self._on_error is not None:
            self._on_error(stage)


def build_scanner_guard(
    cfg: ScannerSettings,
    classifier: Classifier | None = None,
    *,
    on_error: Callable[[str], None] | None = None,
) -> OutputScanner:
    """The scanner of a configuration with its actions, ready for the pipeline's output slot."""
    scanner = CompositeScanner(
        default_rules(cfg.allowed_domains), classifier, cfg, on_error=on_error
    )
    return OutputScanner(scanner, cfg, on_error=on_error)
