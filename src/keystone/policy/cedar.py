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

import json
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
            raise CedarError(str(exc)) from None

    @classmethod
    def from_file(cls, path: Path) -> CedarSchema:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CedarError(f"{path}: cannot be read ({exc.strerror})") from None
        return cls(text)


class CompiledPolicies:
    """A parsed set of Cedar policies. Reused across evaluations: parsing it is most of the cost
    of a decision."""

    def __init__(self, text: str) -> None:
        self.text = text
        try:
            self.handle = cedarpy.PolicySet.from_str(text)
        except ValueError as exc:
            raise CedarError(str(exc)) from None

    @classmethod
    def from_text(cls, text: str) -> CompiledPolicies:
        return cls(text)

    def __len__(self) -> int:
        return len(self.handle)


@dataclass(frozen=True)
class PolicyMeta:
    """What the loader needs to know about one policy in a text: its place, its `@id` (None when
    it has none) and whether it permits or forbids. Cedar calls the policy at `position` (counting
    from 0) `policy<position>`."""

    position: int
    id: str | None
    effect: Literal["permit", "forbid"]


def read_policies(text: str) -> list[PolicyMeta]:
    """Parse a policy text and describe its policies, in order. Raises CedarError for a syntax
    error and for a policy template: a template does nothing until it is linked, so one in a file
    would look like a rule and never apply."""
    try:
        document = json.loads(cedarpy.policies_to_json_str(text))
    except ValueError as exc:
        raise CedarError(str(exc)) from None
    if document.get("templates") or document.get("templateLinks"):
        raise CedarError("policy templates (?principal and ?resource) are not supported")
    found = document.get("staticPolicies", {})
    metas = []
    for name in sorted(found, key=lambda key: int(key.removeprefix("policy"))):
        policy = found[name]
        annotations = policy.get("annotations") or {}
        identifier = annotations.get("id")
        metas.append(
            PolicyMeta(
                position=int(name.removeprefix("policy")),
                id=identifier if isinstance(identifier, str) else None,
                effect="forbid" if policy.get("effect") == "forbid" else "permit",
            )
        )
    return metas


@dataclass(frozen=True)
class ValidationProblem:
    """A mistake the validator found. `position` is the policy it is in, as in PolicyMeta, or
    None when it is not about one policy."""

    position: int | None
    message: str


def validate_policies(text: str, schema: CedarSchema) -> list[ValidationProblem]:
    """Check a policy text against the schema: misspelled attributes, a read of an optional
    attribute without `has`, type errors, unknown entity types and actions."""
    result = cedarpy.validate_policies(text, schema.handle)
    if result.validation_passed:
        return []
    problems = []
    for error in result.errors:
        name = error.policy_id
        position = int(name.removeprefix("policy")) if name.startswith("policy") else None
        problems.append(ValidationProblem(position=position, message=error.error))
    return problems


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
