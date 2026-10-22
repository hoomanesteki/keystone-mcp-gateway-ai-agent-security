#!/usr/bin/env python3
"""Check the repo's prose against the voice rules in docs/PLAN.md section 5.10.

    lint_prose.py [--root DIR]

Two checks:
  1. Banned words and phrases in README.md, CONTRIBUTING.md, docs/** and site/**.
     docs/PLAN.md is skipped because it quotes the banned list.
  2. No em dash (U+2014) in any tracked text file.

Exits 1 when it finds anything. Stdlib only.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# Built from code points so this file never contains the character it hunts for.
EM_DASH = chr(0x2014)
APOSTROPHE = f"['{chr(0x2019)}]"

# Stems cover the forms a writer reaches for ("leverages", "seamlessly"). Each entry is
# (label, pattern).
BANNED = [
    ("leverage", r"\bleverag(?:e|es|ed|ing)\b"),
    ("seamless", r"\bseamless(?:ly)?\b"),
    ("robust", r"\brobust(?:ly|ness)?\b"),
    ("comprehensive", r"\bcomprehensive(?:ly)?\b"),
    ("cutting-edge", r"\bcutting[- ]edge\b"),
    ("state-of-the-art", r"\bstate[- ]of[- ]the[- ]art\b"),
    ("delve", r"\bdelv(?:e|es|ed|ing)\b"),
    ("empower", r"\bempower(?:s|ed|ing|ment)?\b"),
    ("unlock", r"\bunlock(?:s|ed|ing)?\b"),
    ("elevate", r"\belevat(?:e|es|ed|ing)\b"),
    ("game-changer", r"\bgame[- ]chang(?:er|ers|ing)\b"),
    ("supercharge", r"\bsupercharg(?:e|es|ed|ing)\b"),
    ("revolutionize", r"\brevolutioni[sz](?:e|es|ed|ing)\b"),
    ("in today's", rf"\bin today{APOSTROPHE}s\b"),
    ("it's worth noting", rf"\bit{APOSTROPHE}s worth noting\b"),
    ("plays a crucial role", r"\bplay(?:s|ed|ing)? a crucial role\b"),
    ("a testament to", r"\ba testament to\b"),
    ("Furthermore,", r"\bfurthermore,"),
    ("Moreover,", r"\bmoreover,"),
    ("In conclusion", r"\bin conclusion\b"),
    ("dive into", r"\bdiv(?:e|es|ed|ing) into\b"),
    ("navigate the complexities", r"\bnavigat(?:e|es|ed|ing) the complexities\b"),
]
BANNED_RE = [(label, re.compile(pattern, re.IGNORECASE)) for label, pattern in BANNED]

PROSE_FILES = ("README.md", "CONTRIBUTING.md")
PROSE_DIRS = ("docs", "site")
PROSE_EXEMPT = {"docs/PLAN.md"}
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache"}


def candidate_files(root: Path) -> list[str]:
    """Tracked files plus new untracked ones that git does not ignore. Falls back to a walk."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return sorted(line for line in out.splitlines() if line)
    except (subprocess.CalledProcessError, FileNotFoundError):
        found: list[str] = []
        for base, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            found.extend(os.path.relpath(os.path.join(base, n), root) for n in names)
        return sorted(found)


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def is_prose(relative: str) -> bool:
    if relative in PROSE_EXEMPT:
        return False
    return relative in PROSE_FILES or relative.split("/")[0] in PROSE_DIRS


def lint(root: Path) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    for relative in candidate_files(root):
        text = read_text(root / relative)
        if text is None:
            continue
        prose = is_prose(relative)
        for number, line in enumerate(text.splitlines(), start=1):
            if EM_DASH in line:
                findings.append(
                    (relative, number, "em dash, use a comma, colon, period or parentheses")
                )
            if prose:
                for label, pattern in BANNED_RE:
                    if pattern.search(line):
                        findings.append((relative, number, f'banned phrase "{label}"'))
    return findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)

    findings = lint(args.root)
    in_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    for relative, number, message in findings:
        print(f"{relative}:{number}: {message}")
        if in_ci:
            print(f"::error file={relative},line={number}::{message}")
    if findings:
        print(f"{len(findings)} problem(s)", file=sys.stderr)
        return 1
    print("prose ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
