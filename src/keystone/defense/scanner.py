"""The scanner: read what a tool result says, and judge whether it is an instruction (KS-701).

`extract` turns a result into the text a reader of it would see. `CompositeScanner` scores that
text with the rules (`rules.py`) and gives it a label. What is done with a flagged output is
decided elsewhere, by the tool's risk (KS-703), and where the scanner sits in the pipeline is
KS-704. The scanner changes nothing it is given.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import anyio

from keystone.core.types import ScanResult, ToolRef, ToolResult
from keystone.defense.classifier import Classifier
from keystone.defense.rules import Rule, analyze, combine, default_rules, prepare, reveal_tags
from keystone.settings import ScannerSettings, ScannerThresholds

Label = Literal["benign", "suspicious", "injection"]

# Text that is JSON is read as the strings in it. Beyond this size it is read as it is.
MAX_JSON_CHARS = 5_000_000
# What `model` says when the classifier was asked and gave no answer in time.
TIMEOUT = "timeout"


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


class CompositeScanner:
    """Scores a text with the rules and, when there is one, a classifier. The final score is the
    higher of the two: the rules are cheap and exact about what they name, and the classifier sees
    what no pattern names. A classifier that does not answer within `classifier_timeout_ms` is left
    out of that scan, which is then the rules alone, and `model` says "timeout"."""

    def __init__(
        self,
        rules: Sequence[Rule],
        classifier: Classifier | None = None,
        cfg: ScannerSettings | None = None,
    ) -> None:
        self._rules = list(rules)
        self._classifier = classifier
        self._cfg = cfg or ScannerSettings()

    async def scan(self, text: str, *, tool: ToolRef) -> ScanResult:
        started = time.perf_counter()
        window, truncated = self._window(text)
        details = self._rules_pass(window, truncated)
        classifier = self._classifier
        if classifier is not None:
            view = prepare(reveal_tags(window))[0]
            answer = await self._ask(classifier, view)
            score = details.score if answer is None else max(details.score, round(answer, 6))
            details = details.model_copy(
                update={
                    "score": score,
                    "label": label_for(score, self._cfg.thresholds),
                    "model": TIMEOUT if answer is None else classifier.name,
                    "classifier_score": None if answer is None else round(answer, 6),
                }
            )
        return details.model_copy(update={"latency_ms": (time.perf_counter() - started) * 1000})

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

    async def _ask(self, classifier: Classifier, view: str) -> float | None:
        with anyio.move_on_after(self._cfg.classifier_timeout_ms / 1000):
            return await classifier.score(view)
        return None

    def _window(self, text: str) -> tuple[str, bool]:
        """The text, or its two ends when it is longer than the limit."""
        limit = self._cfg.max_scan_chars
        if len(text) <= limit:
            return text, False
        half = limit // 2
        return f"{text[:half]}\n\n{text[-half:]}", True


def build_scanner(cfg: ScannerSettings, classifier: Classifier | None = None) -> CompositeScanner:
    return CompositeScanner(default_rules(cfg.allowed_domains), classifier, cfg)
