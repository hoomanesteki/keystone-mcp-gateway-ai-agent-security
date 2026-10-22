"""Pinning: the rules for holding a changed tool definition until a person has read it (KS-205).

A tool's description is text the model reads, so whoever controls it can instruct the agent. The
registry stores the definition a person accepted (the live one, with its hashes). When an upstream
later lists a different description or schema, the new one waits in `pending_*`, the tool is
quarantined, and nothing reaches the model or the upstream until `approve-change`.
"""

from __future__ import annotations

import difflib
import json
import re
from typing import Any

from keystone.core.canonical import canonical_json, sha256_hex

# Why a tool is not active, kept in `quarantine_reason`.
DESCRIPTION_CHANGED = "description_changed"
SCHEMA_CHANGED = "schema_changed"
SUSPICIOUS = "suspicious_description"  # the screening of a new tool (KS-206)
REMOVED = "removed_from_upstream"  # sync disabled it: the upstream stopped listing it
OPERATOR_DISABLED = "disabled_by_operator"

CHANGE_REASONS = (DESCRIPTION_CHANGED, SCHEMA_CHANGED, f"{DESCRIPTION_CHANGED},{SCHEMA_CHANGED}")


def change_reason(held: tuple[str, str], offered: tuple[str, str]) -> str | None:
    """The `quarantine_reason` for an upstream that offers (description hash, schema hash)
    `offered` where we hold `held`, or None when nothing differs."""
    reasons = []
    if held[0] != offered[0]:
        reasons.append(DESCRIPTION_CHANGED)
    if held[1] != offered[1]:
        reasons.append(SCHEMA_CHANGED)
    return ",".join(reasons) or None


def reason_category(reason: str | None) -> str:
    """The part of a reason that is safe to show an agent: `suspicious_description:hidden_unicode`
    becomes `suspicious_description`, so the agent learns no rule names."""
    return (reason or "").partition(":")[0]


def pending_fingerprint(description: str, schema: dict[str, Any]) -> str:
    """One digest over a whole pending definition. `keystone tool show` prints it, and
    `approve-change --expect` refuses to apply a definition whose digest differs."""
    return sha256_hex(canonical_json([description, schema]))


def schema_text(schema: dict[str, Any] | None) -> str:
    return (
        "" if schema is None else json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False)
    )


def _pieces(text: str) -> list[str]:
    """Split at line ends and sentence ends, because a description is often one long line and a
    diff of whole lines would show the whole description as changed."""
    return [piece for piece in re.split(r"(?<=[.!?])\s+|\n", text) if piece]


def unified_diff(held: str, offered: str, label: str) -> str:
    """A unified diff of two texts, piece by piece. Empty when they are equal."""
    lines = difflib.unified_diff(
        _pieces(held), _pieces(offered), f"{label} (current)", f"{label} (pending)", lineterm=""
    )
    return "\n".join(lines)
