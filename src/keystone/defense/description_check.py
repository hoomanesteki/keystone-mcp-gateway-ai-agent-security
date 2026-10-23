"""Screen a tool definition for text aimed at the model and not at a person (KS-206, KS-706).

A tool description goes into the model's context, and so does the description of each field of its
input schema, so both are places to hide instructions. Two checks read them when a tool is first
seen, and a hit means "a person should read this before the tool is used".

`check_description` is the cheap first check of Phase 2. It finds the crude cases: characters a
reader cannot see, phrases that tell the model to ignore its instructions or to keep something
from the user, and descriptions that try to chain other tools. It reads one text.

`Screener` (KS-706) adds the scanner's rules, the ones that read tool output, over the description
and over every `description` inside the input schema, at any depth. It holds a tool when the
highest score is at or above `scanner.description_threshold`, or when the first check hits. Both
are patterns and understand nothing: a patient attacker writes around any fixed list. A model is
left out on purpose. Descriptions are short and imperative by nature, which is the text the model
gets wrong (ADR-0011): it scored "Return the payload unchanged." 0.998 and "Always fail with the
given message." 0.998, two of the 13 descriptions of the demo tools (the others scored under
0.01). A model that had finished loading would hold the echo tools, and one that had not would
not, and a tool held or not depending on that is worse than one held by rules a reviewer can read.

Only the `description` fields of a schema are read. Its other strings (`title`, `default`, `enum`,
`examples`, property names) are not: a person reads them in the schema, and any change to a
schema holds a tool that was accepted already (KS-205).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from keystone.settings import ScannerSettings

MAX_DESCRIPTION_CHARS = 2000
# More descriptions than this in one schema is a definition no person wrote by hand. Reading them
# all would let an upstream make the registry's sync as slow as it likes, so the schema is held
# as oversized and the rest is not read.
MAX_SCHEMA_DESCRIPTIONS = 1000
# A place is printed in a reason, and a property name comes from the upstream.
MAX_PLACE_CHARS = 80

# Characters that render as nothing, or that reorder the text around them. Tag characters can
# spell a message that no editor shows. The scanner's `hidden_unicode` rule looks for the same
# ranges (KS-701).
HIDDEN_CHARACTERS = re.compile(
    "[\U000e0000-\U000e007f"  # tag characters
    "​-‏"  # zero-width space and joiners, direction marks
    "⁠-⁤"  # word joiner, invisible operators
    "‪-‮"  # bidirectional embeddings and overrides
    "⁦-⁩]"  # bidirectional isolates
)

_APOSTROPHE = "['\u2019]"
_VERBS = r"(?:ignore|disregard|forget|override)"
_OBJECTS = r"(?:instructions?|prompts?|rules|guidelines)"
_EARLIER = r"(?:previous|prior|above|earlier|preceding|other|system|safety)"
_TELL = r"(?:tell|mention|inform|reveal|disclose)"
_THE_USER = rf"the\s+user\b(?!{_APOSTROPHE}s)"  # "the user's name" is about a name, not a secret
# "ignore all previous instructions" and "ignore the previous instructions" break the rule.
# "ignore the rules folder" does not: a bare "the" is not enough.
_INSTRUCTION_OVERRIDE = re.compile(
    rf"\b{_VERBS}\s+(?:all|any|every|your)\s+(?:{_EARLIER}\s+)*{_OBJECTS}\b"
    rf"|\b{_VERBS}\s+(?:the\s+)?{_EARLIER}\s+{_OBJECTS}\b"
    rf"|\bdo\s+not\s+{_TELL}\s+(?:this\s+to\s+)?{_THE_USER}"
    rf"|\bdo(?:n{_APOSTROPHE}t)\s+{_TELL}\s+(?:this\s+to\s+)?{_THE_USER}"
    rf"|\bwithout\s+(?:telling|informing|notifying)\s+{_THE_USER}",
    re.IGNORECASE,
)
_PSEUDO_TAG = re.compile(r"<\s*/?\s*(?:important|system)\b[^>]*>", re.IGNORECASE)
_BEFORE_THIS_TOOL = re.compile(
    r"\bbefore\s+(?:using|you\s+use|calling|you\s+call|invoking|running)\s+this\s+tool\b",
    re.IGNORECASE,
)
_CROSS_TOOL_VERB = re.compile(r"\b(?:read|send|call)\b", re.IGNORECASE)


def check_description(text: str) -> list[str]:
    """The ids of the rules that `text` breaks, in a fixed order. Empty means nothing was found.

    Hidden characters are removed and the text is normalized (NFKC) before the phrase rules run,
    so a zero-width space inside a word does not hide it.
    """
    hits: list[str] = []
    if HIDDEN_CHARACTERS.search(text):
        hits.append("hidden_unicode")
    plain = unicodedata.normalize("NFKC", HIDDEN_CHARACTERS.sub("", text))
    if _INSTRUCTION_OVERRIDE.search(plain):
        hits.append("instruction_override")
    if _PSEUDO_TAG.search(plain):
        hits.append("pseudo_tag")
    if _BEFORE_THIS_TOOL.search(plain) and _CROSS_TOOL_VERB.search(plain):
        hits.append("cross_tool_reference")
    if len(text) > MAX_DESCRIPTION_CHARS:
        hits.append("oversized")
    return hits


def _place(parts: list[str]) -> str:
    """Where a description is, as `input_schema.properties.note`: the names on the way down. A name
    is the upstream's own text, so what is not a letter, a digit or one of `_$-` becomes `?`, and a
    long path is cut."""
    text = "input_schema" + "".join(
        part if part.startswith("[") else "." + re.sub(r"[^\w$-]", "?", part) for part in parts
    )
    return text if len(text) <= MAX_PLACE_CHARS else text[: MAX_PLACE_CHARS - 3] + "..."


def schema_descriptions(
    schema: Mapping[str, Any] | None, limit: int = MAX_SCHEMA_DESCRIPTIONS + 1
) -> list[tuple[str, str]]:
    """(place, text) of every `description` that is a string anywhere in a JSON schema, in the
    order of the document, and no more than `limit` of them. A `description` key whose value is
    not a string is a property of that name and not a description, so it is walked into. It uses a
    stack and not recursion, since a schema nested a thousand deep is a way to crash a function
    that calls itself."""
    found: list[tuple[str, str]] = []
    if not schema:
        return found
    stack: list[tuple[list[str], Any]] = [([], schema)]
    while stack and len(found) < limit:
        path, node = stack.pop()
        if isinstance(node, Mapping):
            text = node.get("description")
            is_text = isinstance(text, str)
            if isinstance(text, str):
                found.append((_place(path), text))
            # Pushed in reverse, so that the first key is the first one read.
            for key in reversed(list(node)):
                if not (is_text and key == "description"):
                    stack.append(([*path, str(key)], node[key]))
        elif isinstance(node, list):
            for index in reversed(range(len(node))):
                stack.append(([*path, f"[{index}]"], node[index]))
    return found


@dataclass(frozen=True)
class Screening:
    """What the screening found in a definition."""

    # The ids of the rules that hit, the first check's before the scanner's, each once.
    hits: tuple[str, ...] = ()
    # The highest score the scanner gave a text that held the tool, or the highest of all when none
    # did. None when the scanner did not read the definition, which is not the same as 0.
    score: float | None = None
    # Where that is: `description`, or a place in the input schema.
    where: str = "description"
    flagged: bool = False

    def reason(self) -> str:
        """What follows `suspicious_description:` in the registry: the rules and, when the scanner
        read the definition, the score and the place:
        `instruction_override,tool_directive score=0.70 in=description`."""
        listed = ",".join(self.hits)
        if self.score is None:
            return listed
        return f"{listed} score={self.score:.2f} in={self.where}"


class RulesResult(Protocol):
    @property
    def score(self) -> float: ...

    @property
    def rule_hits(self) -> list[str]: ...


class TextScanner(Protocol):
    """The scanner's rules over one text, without waiting for anything (`CompositeScanner`)."""

    def scan_text(self, text: str) -> RulesResult: ...


class Screener:
    """Reads a tool's description and the descriptions in its input schema. Built from the
    settings, it uses the scanner's rules and `scanner.description_threshold`. Without a scanner
    (none given, or `scanner.enabled` false) it is the first check on the description alone,
    exactly as before Phase 7."""

    def __init__(self, scanner: TextScanner | None = None, threshold: float = 0.5) -> None:
        self._scanner = scanner
        self._threshold = threshold

    @classmethod
    def from_settings(cls, cfg: ScannerSettings) -> Screener:
        if not cfg.enabled:
            return cls(None, cfg.description_threshold)
        # Imported here: the scanner's rules import this module for the hidden characters.
        from keystone.defense.rules import default_rules
        from keystone.defense.scanner import CompositeScanner

        rules = CompositeScanner(default_rules(cfg.allowed_domains), None, cfg)
        return cls(rules, cfg.description_threshold)

    def screen(self, description: str, schema: Mapping[str, Any] | None = None) -> Screening:
        scanner = self._scanner
        if scanner is None:
            first = check_description(description)
            return Screening(tuple(first), None, "description", bool(first))
        found = schema_descriptions(schema)
        texts = [("description", description), *found[:MAX_SCHEMA_DESCRIPTIONS]]
        cheap: list[str] = []
        rules: list[str] = []
        held: tuple[float, str] | None = None  # the highest score among the texts that held it
        highest: tuple[float, str] = (0.0, "description")
        for place, text in texts:
            first = check_description(text)
            scanned = scanner.scan_text(text)
            over = bool(scanned.rule_hits) and scanned.score >= self._threshold
            cheap += [hit for hit in first if hit not in cheap]
            if over:
                rules += [hit for hit in scanned.rule_hits if hit not in rules]
            if (first or over) and (held is None or scanned.score > held[0]):
                held = (scanned.score, place)
            if scanned.score > highest[0]:
                highest = (scanned.score, place)
        if len(found) > MAX_SCHEMA_DESCRIPTIONS:
            if "oversized" not in cheap:
                cheap.append("oversized")
            held = held or (0.0, "input_schema")
        hits = (*cheap, *(hit for hit in rules if hit not in cheap))
        score, where = held or highest
        return Screening(hits, score, where, held is not None)
