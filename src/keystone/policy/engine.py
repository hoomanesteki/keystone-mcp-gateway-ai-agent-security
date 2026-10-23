"""The two-pass policy engine (KS-404, plan section 3.8).

Read this file for one rule: every path that does not end in an explicit allow ends in a deny.

    pass 1, access set     standard Cedar. Deny: the determining forbids are the reasons, or
                           `default-deny` when nothing matched. Allow: go on.
    pass 2, approval set   permits only. One matches: `require_approval`, with the matching ids as
                           reasons. None does: allow, with the access permits as reasons. A tool
                           listing stops after pass 1, because "who may see it" is not "when a
                           person must look".

There is exactly one place that returns `Effect.ALLOW` (the end of `_decide`), and it is reached
only after both passes answered cleanly. Everything else is a deny:

- a policy that failed to evaluate, in either pass (`errors` is not empty). Cedar skips such a
  policy, so a broken `forbid` would otherwise not forbid and a broken approval permit would not
  ask;
- a request Cedar could not decide (it does not fit the schema): no decision is not an allow;
- no policies for the tenant, no policy set loaded, or any exception: the decision is `deny` with
  the reason `policy-error`, and the cause goes to the log, never to the caller.

The audit log therefore shows `policy-error` for the "something is wrong with the rules" case and
`default-deny` for the ordinary "nothing allows this" case.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import structlog

from keystone.core.types import Decision, Effect, Principal, ToolRef
from keystone.policy.cedar import CedarSchema, CedarVerdict, CompiledPolicies, authorize
from keystone.policy.entities import Action, build_entities, build_request
from keystone.policy.store import PolicySet, PolicyStore

log = structlog.get_logger()

DEFAULT_DENY = "default-deny"
POLICY_ERROR = "policy-error"
# A Cedar message can quote the whole entity list. Enough to see the cause, not enough to flood.
MAX_ERROR_CHARS = 300


class PolicyEngine(Protocol):
    """What the gateway needs of a policy engine (plan section 3.6). The policy slot and the tool
    listing depend on this and not on Cedar."""

    @property
    def version(self) -> str: ...

    def evaluate(
        self, principal: Principal, action: Action, tool: ToolRef, context: Mapping[str, Any]
    ) -> Decision: ...


class EvaluationFailed(Exception):
    """The rules could not give an answer. The decision is a deny with `policy-error`."""

    def __init__(self, why: str, errors: Sequence[str] = ()) -> None:
        super().__init__(why)
        self.errors = tuple(e[:MAX_ERROR_CHARS] for e in errors)


@dataclass(frozen=True)
class Trace:
    """A decision with the policies that decided each pass. The policy test runner reads it to
    say which policies a set of cases exercised."""

    decision: Decision
    access: tuple[str, ...]
    approval: tuple[str, ...]


@dataclass(frozen=True)
class _Outcome:
    effect: Effect
    reasons: tuple[str, ...]
    access: tuple[str, ...] = ()
    approval: tuple[str, ...] = ()


class CedarPolicyEngine:
    """Implements `PolicyEngine` (plan section 3.6) over the policy set the store has in force."""

    def __init__(self, store: PolicyStore) -> None:
        self._store = store

    @property
    def version(self) -> str:
        return self._store.version

    def evaluate(
        self,
        principal: Principal,
        action: Action,
        tool: ToolRef,
        context: Mapping[str, Any],
    ) -> Decision:
        return self.trace(principal, action, tool, context).decision

    def trace(
        self,
        principal: Principal,
        action: Action,
        tool: ToolRef,
        context: Mapping[str, Any],
    ) -> Trace:
        started = time.perf_counter()
        snapshot: PolicySet | None = None
        try:
            # One read, so a reload in the middle of a call cannot mix two sets.
            snapshot = self._store.current
            outcome = self._decide(snapshot, principal, action, tool, context)
        except EvaluationFailed as failure:
            log.error(
                "policy_evaluation_failed",
                why=str(failure),
                errors=list(failure.errors),
                tenant=principal.tenant_id,
                tool=tool.name,
                action=action,
                version=snapshot.version if snapshot else None,
            )
            outcome = _Outcome(Effect.DENY, (POLICY_ERROR,))
        except Exception:
            log.exception(
                "policy_evaluation_crashed",
                tenant=principal.tenant_id,
                tool=tool.name,
                action=action,
            )
            outcome = _Outcome(Effect.DENY, (POLICY_ERROR,))
        decision = Decision(
            effect=outcome.effect,
            reasons=list(outcome.reasons),
            source="policy",
            policy_version=snapshot.version if snapshot else None,
            evaluated_ms=(time.perf_counter() - started) * 1000,
        )
        return Trace(decision, outcome.access, outcome.approval)

    def _decide(
        self,
        snapshot: PolicySet,
        principal: Principal,
        action: Action,
        tool: ToolRef,
        context: Mapping[str, Any],
    ) -> _Outcome:
        tenant = snapshot.tenants.get(principal.tenant_id)
        if tenant is None:
            raise EvaluationFailed(f"no policies are loaded for tenant {principal.tenant_id!r}")
        entities = build_entities(principal, tool)
        request = build_request(principal, action, tool, context)

        access = _ask("access", tenant.access, snapshot.schema, entities, request)
        if access.decision == "deny":
            return _Outcome(Effect.DENY, access.reasons or (DEFAULT_DENY,), access=access.reasons)
        if access.decision != "allow" or not access.reasons:
            # `_ask` has refused every other answer. This keeps a new kind of answer, or an allow
            # that names no policy, from slipping through as an allow.
            raise EvaluationFailed("the access set gave an answer that is not an explicit allow")

        if action == "list_tool":
            return _Outcome(Effect.ALLOW, access.reasons, access=access.reasons)

        approval = _ask("approval", tenant.approval, snapshot.schema, entities, request)
        if approval.decision == "allow":
            return _Outcome(
                Effect.REQUIRE_APPROVAL,
                approval.reasons,
                access=access.reasons,
                approval=approval.reasons,
            )
        if approval.decision == "deny" and not approval.reasons:
            # No approval permit matched. A deny that names a policy would be a forbid in the
            # approval set, which the loader refuses; it is not read as "no approval needed".
            return _Outcome(Effect.ALLOW, access.reasons, access=access.reasons)
        raise EvaluationFailed("the approval set gave an answer that is not a clean yes or no")


def _ask(
    which: str,
    policies: CompiledPolicies,
    schema: CedarSchema,
    entities: Sequence[Mapping[str, Any]],
    request: Mapping[str, Any],
) -> CedarVerdict:
    verdict = authorize(policies, schema, entities, request)
    if verdict.errors or verdict.decision == "none":
        raise EvaluationFailed(f"the {which} set could not be evaluated", verdict.errors)
    return verdict
