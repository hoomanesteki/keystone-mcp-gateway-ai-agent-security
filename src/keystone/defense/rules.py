"""Rules for text that tries to steer the model that reads it (KS-701).

A rule is a small, readable check with a weight. It names the phrases it looks for, so a reviewer
who is told "instruction_override, secrecy" knows what was found and can read the pattern. The
score of a text is the chance that at least one hit is real, taking each weight as the chance of
that rule alone: `1 - (1 - w1) * (1 - w2) * ...`. One weak rule is not enough to flag a text, and
several together are.

What the rules are not. They are patterns and understand nothing. Someone who knows the list
writes around it, and a text in a language or a style that no pattern names is not seen at all.
That is the classifier's job (KS-702). The rules are the cheap first look: they run in a
millisecond on 10 KB, they need no model, and the demo does not depend on anything else.

The text is looked at in two ways. `hidden_unicode` reads it as it came. The other rules read it
with the invisible characters taken out and the rest normalized (NFKC), so a zero-width space in
the middle of a word, or fullwidth letters, do not hide a phrase from them.

A rule never looks for the `ks-do` marker of the naive agent (examples/injections.py): a detector
that recognised it would look better on planted attacks than it is on real ones.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from itertools import islice
from typing import Literal, NamedTuple
from urllib.parse import urlsplit

from keystone.defense.description_check import HIDDEN_CHARACTERS

# A rule that hits more often than this has its first hits kept and the rest dropped. Redaction
# needs the places; a score needs only the fact.
MAX_SPANS = 50
# A run of base64 is read when it is longer than this (the story's figure), and no more than this
# many runs of a text are decoded.
MIN_ENCODED_CHARS = 200
MAX_DECODED_RUNS = 8
# What an encoded payload adds when it decodes to something another rule hits.
DECODED_WEIGHT = 0.5

ENCODED_PAYLOAD = "encoded_payload"
ENCODED_PAYLOAD_DECODED = "encoded_payload_decoded"
DECODED_PREFIX = "decoded:"


class Span(NamedTuple):
    """A stretch of the text a rule hit: `text[start:end]`."""

    start: int
    end: int


@dataclass(frozen=True)
class Rule:
    id: str
    weight: float
    check: Callable[[str], list[Span]]
    # The text the rule reads: "raw" is the text as it came, "plain" has the invisible characters
    # taken out and is normalized, and "lower" is plain in lower case. A pattern that is written in
    # lower case and matched against lower case text runs about twice as fast as one that ignores
    # case, which matters when every tool output goes through it.
    view: Literal["raw", "plain", "lower"] = "plain"


@dataclass(frozen=True)
class Hit:
    id: str
    weight: float
    spans: tuple[Span, ...] = ()


def combine(weights: Iterable[float]) -> float:
    """`1 - (1 - w1) * (1 - w2) * ...`: the chance that at least one hit is real."""
    miss = 1.0
    for weight in weights:
        miss *= 1.0 - weight
    return 1.0 - miss


def _spans(pattern: re.Pattern[str]) -> Callable[[str], list[Span]]:
    def check(text: str) -> list[Span]:
        return [Span(m.start(), m.end()) for m in islice(pattern.finditer(text), MAX_SPANS)]

    return check


# -- instruction_override

_VERBS = r"(?:ignore|disregard|forget|override)"
_OBJECTS = r"(?:instructions?|prompts?|rules|guidelines|directives|commands)"
_EARLIER = r"(?:previous|prior|above|earlier|preceding|other|system|safety|original|initial)"
# "ignore all previous instructions" and "ignore the previous instructions" are overrides.
# "ignore the warning" and "ignore the rules folder" are not: a bare "the" is not enough.
_INSTRUCTION_OVERRIDE = re.compile(
    rf"\b{_VERBS}\s+(?:all|any|every|your|my)\s+(?:(?:of\s+)?(?:the|your|my)\s+)?"
    rf"(?:{_EARLIER}\s+)*{_OBJECTS}\b"
    rf"|\b{_VERBS}\s+(?:the\s+|these\s+|those\s+)?{_EARLIER}\s+(?:{_EARLIER}\s+)*{_OBJECTS}\b"
    r"|\b(?:ignore|disregard|forget)\s+everything\s+"
    r"(?:above|before|so\s+far|you\s+(?:were|have\s+been)\s+told)\b"
    # The same phrase in the languages that attacks come in most. This is a phrase list, not
    # language understanding.
    r"|\bignora(?:r|d)?\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)\b"
    r"|\bolvida\s+(?:todas\s+)?las\s+instrucciones\b"
    r"|\bignore[zr]?\s+(?:toutes\s+)?les\s+instructions\s+(?:pr[ée]c[ée]dentes|ant[ée]rieures)\b"
    r"|\bignorier(?:e|en|t)?\s+(?:alle\s+)?(?:vorherigen|bisherigen|obigen|fr[üu]heren)\s+"
    r"(?:anweisungen|instruktionen|befehle)\b"
    r"|\bignor[ea]\s+(?:todas\s+)?as\s+instru[çc][õo]es\s+anteriores\b"
    r"|\bignora\s+(?:tutte\s+)?le\s+istruzioni\s+precedenti\b"
)

# -- role_spoof

_ROLE_SPOOF = re.compile(
    # A chat label at the start of a line, or a heading that names a role.
    r"^[ \t]*(?:system|assistant|developer)[ \t]*:"
    r"|^[ \t]*#{1,6}[ \t]*(?:system|assistant|instructions?)\b"
    # Tokens of chat templates: <|im_start|>, <|system|>, [INST], <<SYS>>.
    r"|<\|[a-z_]{2,20}\|>|\[/?inst\]|<</?sys>>"
    # Tags that dress a text as a message from above, and a bracketed label such as [SYSTEM NOTICE].
    r"|<\s*/?\s*(?:system|important|information|instructions?)\s*>"
    r"|^[ \t]*\[[ \t]*system\b[^\]\n]{0,40}\]",
    re.MULTILINE,
)

# -- hidden_unicode

_HIDDEN_RUN = re.compile(HIDDEN_CHARACTERS.pattern + "+")
# U+200B to U+200F are zero-width characters and direction marks, which real text uses: a joiner in
# an emoji sequence, a non-joiner in Persian, a direction mark beside Arabic, a space in Thai. The
# rest of the ranges (tag characters, bidirectional overrides and isolates, the word joiner and the
# invisible operators) have no use in text a person reads.
_TYPOGRAPHIC = re.compile("[​-‏]+")


def _pictographic(char: str) -> bool:
    code = ord(char)
    return 0x1F000 <= code <= 0x1FAFF or 0x2190 <= code <= 0x2BFF or code == 0xFE0F


def _typographic_neighbour(char: str) -> bool:
    """Whether a character beside a zero-width one makes the zero-width one part of the writing:
    an emoji, or a letter or mark outside ASCII."""
    if not char or char.isascii():
        return False
    return _pictographic(char) or unicodedata.category(char)[0] in "LM"


def _hidden_unicode(text: str) -> list[Span]:
    if text.isascii():
        return []  # every hidden character is outside ASCII, and most text is not
    found: list[Span] = []
    for run in _HIDDEN_RUN.finditer(text):
        start, end = run.span()
        if _TYPOGRAPHIC.fullmatch(run.group()):
            before = text[start - 1] if start else ""
            after = text[end] if end < len(text) else ""
            if _typographic_neighbour(before) or _typographic_neighbour(after):
                continue
        found.append(Span(start, end))
        if len(found) >= MAX_SPANS:
            break
    return found


# -- tool_directive

_EMAIL = r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+"
_TOOL_PHRASE = re.compile(
    # "call the send_email tool", "use the mail__send_email tool".
    r"\b(?:call|use|run|invoke|execute|trigger)\s+(?:the\s+)?[a-z0-9_.\-]{2,64}\s+tool\b"
    # "run mail__send_email": a tool named the way Keystone names them.
    r"|\b(?:call|use|run|invoke|execute|trigger)\s+(?:the\s+)?[a-z0-9]+__[a-z0-9_]+\b"
)
# "send ... to <address>" and "transfer ... to account" are found from the end: the address or the
# word "account" is rare, and the verb is looked for in the sentence before it. Starting from the
# verb instead costs a scan ahead for every "send" in the text.
_TO_ADDRESS = re.compile(rf"\bto\s+{_EMAIL}")
_SEND = re.compile(r"\b(?:send|forward|email|mail|share|upload|post|transmit)\b")
_TO_ACCOUNT = re.compile(r"\bto\s+(?:the\s+)?(?:account|acct)\b")
_TRANSFER = re.compile(r"\btransfer\b")
LOOKBACK_CHARS = 120


def _verb_before(text: str, end: int, verb: re.Pattern[str]) -> int | None:
    """Where `verb` starts in the sentence that ends at `end`, looking back no further than
    LOOKBACK_CHARS and not past a full stop or a line break."""
    floor = max(0, end - LOOKBACK_CHARS)
    before = text[floor:end]
    cut = max(before.rfind("."), before.rfind("\n")) + 1
    found = verb.search(before, cut)
    return floor + found.start() if found else None


def _tool_directive(text: str) -> list[Span]:
    found = [Span(m.start(), m.end()) for m in islice(_TOOL_PHRASE.finditer(text), MAX_SPANS)]
    for anchor, verb in ((_TO_ADDRESS, _SEND), (_TO_ACCOUNT, _TRANSFER)):
        for match in islice(anchor.finditer(text), MAX_SPANS):
            at = _verb_before(text, match.start(), verb)
            if at is not None:
                found.append(Span(at, match.end()))
    found.sort()
    return found[:MAX_SPANS]


# -- secrecy

_SECRECY = re.compile(
    r"\b(?:do\s+not|don['\u2019]t)\s+(?:tell|mention|inform|notify|alert|reveal|disclose)\b"
    r"[^.\n]{0,40}?\b(?:the|your)\s+(?:user|human|owner|operator)\b"
    r"|\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+|your\s+)?"
    r"(?:user|human|owner|operator|anyone|them)\b"
    r"|\bsecretly\b"
    r"|\b(?:do\s+not|don['\u2019]t)\s+(?:ask\s+for|wait\s+for|request|seek)\s+(?:any\s+)?"
    r"(?:confirmation|approval|permission)\b"
    r"|\bkeep\s+(?:this|it|that)\s+(?:a\s+)?(?:secret|hidden|between\s+us|from\s+the\s+user)\b"
)

# -- markdown_exfil

# The part of a markdown image or link that follows its label: `](`, an address, and anything up
# to the closing parenthesis (a title). The label is found by looking back for its bracket, which
# costs one look per link and not one per `[` in the text.
_LINK_TARGET = re.compile(r"\]\(\s*(https?://[^\s)]{1,2048})[^)]{0,200}\)", re.IGNORECASE)
LONG_QUERY_CHARS = 32
LABEL_CHARS = 200


def _markdown_exfil(allowed_domains: Sequence[str]) -> Callable[[str], list[Span]]:
    """An image or link whose address carries a query longer than 32 characters, or an image that
    points to a host that is not allowed. A conversation leaves in a long query, and an image is
    fetched without a click. A link with a short query to a host that is not listed is ordinary
    text: flagging it would flag most pages."""
    allowed = tuple(domain.lower() for domain in allowed_domains)

    def check(text: str) -> list[Span]:
        found: list[Span] = []
        for match in _LINK_TARGET.finditer(text):
            opening = text.rfind("[", max(0, match.start() - LABEL_CHARS - 1), match.start())
            if opening == -1 or "\n" in text[opening : match.start()]:
                continue
            try:
                parts = urlsplit(match.group(1))
                host = (parts.hostname or "").lower()
            except ValueError:
                continue
            is_image = opening > 0 and text[opening - 1] == "!"
            listed = any(host == d or host.endswith("." + d) for d in allowed)
            if len(parts.query) > LONG_QUERY_CHARS or (is_image and not listed):
                found.append(Span(opening - 1 if is_image else opening, match.end()))
                if len(found) >= MAX_SPANS:
                    break
        return found

    return check


# -- encoded_payload

_BASE64_RUN = re.compile(rf"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{{{MIN_ENCODED_CHARS},}}={{0,2}}")


def _decode(run: str) -> str | None:
    """The text a base64 run spells, or None when it is not valid base64 or spells nothing."""
    try:
        raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    text = raw.decode("utf-8", errors="ignore")
    return text if text.strip() else None


# -- the list

RULE_IDS = (
    "instruction_override",
    "role_spoof",
    "hidden_unicode",
    "tool_directive",
    "secrecy",
    "markdown_exfil",
    ENCODED_PAYLOAD,
)


def default_rules(allowed_domains: Iterable[str] = ()) -> list[Rule]:
    """The rules, in the order they are reported. `allowed_domains` are the hosts a markdown image
    may point to (`scanner.allowed_domains`)."""
    return [
        Rule("instruction_override", 0.6, _spans(_INSTRUCTION_OVERRIDE), view="lower"),
        Rule("role_spoof", 0.5, _spans(_ROLE_SPOOF), view="lower"),
        Rule("hidden_unicode", 0.9, _hidden_unicode, view="raw"),
        Rule("tool_directive", 0.4, _tool_directive, view="lower"),
        Rule("secrecy", 0.5, _spans(_SECRECY), view="lower"),
        Rule("markdown_exfil", 0.7, _markdown_exfil(tuple(allowed_domains))),
        Rule(ENCODED_PAYLOAD, 0.2, _spans(_BASE64_RUN)),
    ]


def prepare(text: str) -> tuple[str, bool]:
    """The text the phrase rules read, and whether normalizing it changed anything. Invisible
    characters are removed first (`hidden_unicode` has already seen them), so what changes the text
    is NFKC alone: fullwidth letters, ligatures, compatibility forms."""
    visible = HIDDEN_CHARACTERS.sub("", text)
    if visible.isascii():
        return visible, False
    plain = unicodedata.normalize("NFKC", visible)
    return plain, plain != visible


def _run(rules: Sequence[Rule], raw: str, plain: str) -> list[Hit]:
    views = {"raw": raw, "plain": plain}
    hits: list[Hit] = []
    for rule in rules:
        if rule.view == "lower" and "lower" not in views:
            views["lower"] = plain.lower()
        spans = rule.check(views[rule.view])
        if spans:
            hits.append(Hit(rule.id, rule.weight, tuple(spans)))
    return hits


class Analysis(NamedTuple):
    hits: list[Hit]
    # Whether NFKC changed the text the phrase rules read (fullwidth letters, ligatures).
    normalized: bool


def analyze(text: str, rules: Sequence[Rule]) -> Analysis:
    """The rules that `text` breaks, in the order of `rules`, and whether it was normalized.

    A long run of base64 is decoded once, and the text it spells is read by the other rules. If any
    of them hits, `encoded_payload_decoded` adds 0.5 and each rule that hit is named, with a
    weight of 0, as `decoded:<id>`. The decoded text is not decoded in its turn.
    """
    plain, normalized = prepare(text)
    hits = _run(rules, text, plain)
    encoded = next((hit for hit in hits if hit.id == ENCODED_PAYLOAD), None)
    if encoded is None:
        return Analysis(hits, normalized)
    others = [rule for rule in rules if rule.id != ENCODED_PAYLOAD]
    inner: list[Hit] = []
    for span in encoded.spans[:MAX_DECODED_RUNS]:
        decoded = _decode(plain[span.start : span.end])
        if decoded is None:
            continue
        inner_plain, _ = prepare(decoded)
        inner += _run(others, decoded, inner_plain)
    if inner:
        hits.append(Hit(ENCODED_PAYLOAD_DECODED, DECODED_WEIGHT))
        for rule_id in dict.fromkeys(hit.id for hit in inner):
            hits.append(Hit(f"{DECODED_PREFIX}{rule_id}", 0.0))
    return Analysis(hits, normalized)


def find_hits(text: str, rules: Sequence[Rule]) -> list[Hit]:
    """`analyze` without the normalization flag."""
    return analyze(text, rules).hits
