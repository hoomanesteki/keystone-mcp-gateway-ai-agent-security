"""Screen a tool description for text that is aimed at the model and not at a person (KS-206).

A tool description goes into the model's context, so it is a place to hide instructions. This is
the cheap first check, run when a tool is first seen. It finds the crude cases: characters a
reader cannot see, phrases that tell the model to ignore its instructions or to keep something
from the user, and descriptions that try to chain other tools. It does not understand text. A
patient attacker writes around any fixed list. Phase 7 puts the full scanner behind this same
function name; until then a hit only means "a person should read this before the tool is used".
"""

from __future__ import annotations

import re
import unicodedata

MAX_DESCRIPTION_CHARS = 2000

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
