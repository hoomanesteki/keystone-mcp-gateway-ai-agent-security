#!/usr/bin/env python3
"""Check a commit subject: conventional commit, lowercase, imperative, at most 72 characters.

    check_commit_msg.py <message-file | subject>

The local commit-msg hook runs this under the system python3 (3.9 on macOS), so keep it
stdlib-only and free of newer syntax.
"""

from __future__ import annotations

import os
import re
import sys

TYPES = ("feat", "fix", "test", "docs", "refactor", "perf", "chore", "ci", "build")
MAX_LENGTH = 72
# Merge commits come from `git merge --no-ff`, and release merges from the gate.
ALLOWED_PREFIXES = ("Merge branch", "Release v")

SUBJECT = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[a-z0-9][a-z0-9-]*)\))?(?P<bang>!)?: (?P<text>\S.*)$"
)

# Past-tense or gerund first words are the usual way a subject stops being imperative.
# These end in "ed" or "ing" but are imperative verbs or plain nouns.
IMPERATIVE_EXCEPTIONS = {
    "embed", "feed", "seed", "speed", "need", "proceed", "succeed", "exceed", "bleed", "breed",
    "shed", "shred", "bring", "string", "swing", "sing", "ping", "spring", "wring", "cling",
}  # fmt: skip
# Third-person forms ("adds", "fixes") that the suffix test cannot see.
COMMON_VERBS = {
    "add", "fix", "update", "remove", "change", "rename", "move", "drop", "bump", "use", "make",
    "wire", "set", "run", "call", "handle", "keep", "show", "print", "write", "read", "split",
    "merge", "replace", "introduce", "require", "reject", "allow", "enable", "disable", "mark",
    "record", "pin", "lock", "check", "test", "build", "clean", "document", "explain", "extract",
    "guard", "log", "load", "rework", "simplify", "skip", "start", "stop", "track", "trim",
    "validate", "verify", "cover", "create", "delete", "expose", "group", "hide", "limit",
}  # fmt: skip


THIRD_PERSON = {
    (verb[:-1] + "ies")
    if verb.endswith("y")
    else verb + ("es" if verb.endswith(("sh", "ch", "x")) else "s")
    for verb in COMMON_VERBS
}


def problems(subject: str) -> list[str]:
    if subject.startswith(ALLOWED_PREFIXES):
        return []
    found: list[str] = []
    if len(subject) > MAX_LENGTH:
        found.append(f"subject is {len(subject)} characters, the limit is {MAX_LENGTH}")
    match = SUBJECT.match(subject)
    if not match:
        found.append(
            "expected 'type(scope): summary' with a lowercase type and a space after the colon"
        )
        return found
    if match["type"] not in TYPES:
        found.append(f"unknown type '{match['type']}', use one of: {', '.join(TYPES)}")
    text = match["text"]
    first = text.split()[0]
    if first[0].isupper():
        found.append("start the summary with a lowercase word")
    word = first.lower().strip(",:;")
    if word not in IMPERATIVE_EXCEPTIONS and (
        (word.endswith("ed") and len(word) > 3) or (word.endswith("ing") and len(word) > 4)
    ):
        found.append(f"'{first}' is not imperative, write 'add' not 'added' or 'adding'")
    elif word in THIRD_PERSON:
        found.append(f"'{first}' is not imperative, write the base verb")
    if text.endswith("."):
        found.append("no trailing period")
    return found


def read_subject(argument: str) -> str:
    if os.path.isfile(argument):
        with open(argument, encoding="utf-8") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if line.strip() and not line.startswith("#"):
                    return line
        return ""
    return argument.splitlines()[0] if argument.strip() else ""


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_commit_msg.py <message-file | subject>", file=sys.stderr)
        return 2
    subject = read_subject(argv[1])
    found = problems(subject) if subject else ["the commit message is empty"]
    for message in found:
        print(f"commit message: {message}: {subject!r}", file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error title=commit subject::{message}: {subject}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
