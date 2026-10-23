"""The one place that imports cedarpy (ADR-0006, docs/spikes/cedarpy.md).

The rest of the policy package works with the small typed values here. That keeps the loose
types of the wrapper, and the details of what it reports, in a single file.

What this module guarantees to its callers:
- A schema or a policy set is parsed once, into a handle that every evaluation reuses.
- A reason is the `@id` of a determining policy, never Cedar's positional name.
- `authorize` never raises for a request Cedar cannot decide. It returns a verdict whose decision
  is "none" and whose errors say why, so a caller cannot mistake a failure for a decision.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import cedarpy


class CedarError(Exception):
    """Cedar could not read a schema or a policy text. The message is safe to show an operator."""


class CedarSchema:
    """A parsed schema in Cedar's human-readable format, read from the one source file."""

    def __init__(self, text: str) -> None:
        self.text = text
        try:
            self.handle = cedarpy.Schema.from_str(text)
        except ValueError as exc:
            raise CedarError(f"the schema cannot be read: {exc}") from None

    @classmethod
    def from_file(cls, path: Path) -> CedarSchema:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CedarError(f"the schema {path} cannot be read: {exc.strerror}") from None
        return cls(text)


class CompiledPolicies:
    """A parsed set of Cedar policies. Reused across evaluations: parsing it is most of the cost
    of a decision."""

    def __init__(self, text: str) -> None:
        self.text = text
        try:
            self.handle = cedarpy.PolicySet.from_str(text)
        except ValueError as exc:
            raise CedarError(f"the policies cannot be read: {exc}") from None

    @classmethod
    def from_text(cls, text: str) -> CompiledPolicies:
        return cls(text)

    def __len__(self) -> int:
        return len(self.handle)


@dataclass(frozen=True)
class CedarVerdict:
    """What Cedar said about one request.

    `decision` is "allow" or "deny" when Cedar evaluated the request, and "none" when it could not
    (the request does not fit the schema, say). `reasons` are the `@id` of each determining
    policy, sorted: the permits that matched for an allow, the forbids that matched for a deny, and
    nothing for a deny that no policy asked for. `errors` are the problems Cedar reported. A
    non-empty `errors` next to an "allow" means a policy failed to evaluate and was skipped.
    """

    decision: Literal["allow", "deny", "none"]
    reasons: tuple[str, ...]
    errors: tuple[str, ...]


_DECISIONS: dict[Any, Literal["allow", "deny", "none"]] = {
    cedarpy.Decision.Allow: "allow",
    cedarpy.Decision.Deny: "deny",
    cedarpy.Decision.NoDecision: "none",
}


def _verdict(result: cedarpy.AuthzResult) -> CedarVerdict:
    diagnostics = result.diagnostics
    ids = diagnostics.id_annotations_by_reason
    # A reason with no @id (the loader refuses such a policy) keeps Cedar's own name.
    reasons = tuple(sorted(ids.get(reason, reason) for reason in diagnostics.reasons))
    return CedarVerdict(
        decision=_DECISIONS.get(result.decision, "none"),
        reasons=reasons,
        errors=tuple(diagnostics.errors),
    )


def authorize(
    policies: CompiledPolicies,
    schema: CedarSchema,
    entities: Sequence[Mapping[str, Any]],
    request: Mapping[str, Any],
) -> CedarVerdict:
    """Evaluate one request, validating the request, the context and the entities against the
    schema. `request` carries `principal`, `action` and `resource` as {"type", "id"} dicts and the
    `context` as a dict."""
    result = cedarpy.is_authorized(
        dict(request), policies.handle, [dict(entity) for entity in entities], schema=schema.handle
    )
    return _verdict(result)
