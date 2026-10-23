"""Principals, tools and the call context as Cedar entities and requests (KS-402).

The shapes follow `policies/schema.cedarschema`. Everything here is plain dicts in Cedar's JSON
form, and none of it needs cedarpy, so the builders can be read and tested on their own.

Ids go to Cedar as {"type", "id"} dicts and never inside a Cedar string. A user id comes from a
token and a tool name from an upstream, and either could hold a quote or a backslash that would
change what a string means.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal

from keystone.core.types import RISK_LEVEL, CallContext, Principal, SessionState, ToolRef

NAMESPACE = "Keystone"

Action = Literal["call_tool", "list_tool"]
Uid = dict[str, str]


def entity_uid(kind: str, name: str) -> Uid:
    return {"type": f"{NAMESPACE}::{kind}", "id": name}


def user_uid(tenant_id: str, user_id: str) -> Uid:
    """Qualified by tenant: the same user id in two tenants is two users. A tenant id never
    holds a colon, so the pair cannot be read two ways."""
    return entity_uid("User", f"{tenant_id}:{user_id}")


def tool_uid(name: str) -> Uid:
    return entity_uid("Tool", name)


def action_uid(action: Action) -> Uid:
    return entity_uid("Action", action)


def _reference(kind: str, name: str) -> dict[str, Uid]:
    return {"__entity": entity_uid(kind, name)}


def build_entities(principal: Principal, tool: ToolRef) -> list[dict[str, Any]]:
    """Every entity a decision about `tool` by `principal` can read: both tenants, the groups,
    the user, the tool's upstream and the tool."""
    found: dict[tuple[str, str], dict[str, Any]] = {}

    def add(
        kind: str,
        name: str,
        attrs: dict[str, Any] | None = None,
        parents: list[Uid] | None = None,
    ) -> None:
        found.setdefault(
            (kind, name),
            {"uid": entity_uid(kind, name), "attrs": attrs or {}, "parents": parents or []},
        )

    groups = list(dict.fromkeys(principal.groups))
    add("Tenant", principal.tenant_id)
    add("Tenant", tool.tenant_id)
    for group in groups:
        add("Group", group)
    found[("User", f"{principal.tenant_id}:{principal.user_id}")] = {
        "uid": user_uid(principal.tenant_id, principal.user_id),
        "attrs": {"tenant": _reference("Tenant", principal.tenant_id)},
        "parents": [entity_uid("Group", group) for group in groups],
    }
    add("Upstream", tool.upstream_id, {"tenant": _reference("Tenant", tool.tenant_id)})
    add(
        "Tool",
        tool.name,
        {
            "tenant": _reference("Tenant", tool.tenant_id),
            "risk": tool.risk.value,
            "risk_level": RISK_LEVEL[tool.risk],
            # An attribute named `tags`, not Cedar's entity tags (docs/spikes/cedarpy.md).
            "tags": sorted(tag.value for tag in tool.tags),
        },
        [entity_uid("Upstream", tool.upstream_id)],
    )
    return list(found.values())


def build_context(
    source: CallContext | SessionState,
    extracted: Mapping[str, int | str | bool] | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The context record of the schema, from a call or from a session alone (a tool listing has
    no call). `extracted` is the arguments the policy may read; a call that is given none uses the
    ones it extracted. The hour is the call's own time in UTC, or `now` for a session."""
    if isinstance(source, CallContext):
        principal, session, when = source.principal, source.session, source.received_at
        args = source.extracted if extracted is None else extracted
    else:
        principal, session, when = source.principal, source, now or datetime.now(UTC)
        args = extracted or {}
    return {
        "agent_id": principal.agent_id,
        "agent_trust": principal.agent_trust,
        "session_flags": sorted(flag.value for flag in session.flags),
        "session_tainted": session.tainted,
        "call_count": session.call_count,
        "hour_utc": when.astimezone(UTC).hour,
        # Passed as it is: a key the schema does not know is refused by Cedar, and the call is
        # denied, so a stale extractor cannot go unnoticed.
        "args": dict(args),
    }


def build_request(
    principal: Principal, action: Action, tool: ToolRef, context: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "principal": user_uid(principal.tenant_id, principal.user_id),
        "action": action_uid(action),
        "resource": tool_uid(tool.name),
        "context": dict(context),
    }
