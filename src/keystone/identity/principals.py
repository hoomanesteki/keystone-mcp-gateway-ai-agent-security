"""From the claims of a validated token to the Principal that later steps rely on (KS-303, KS-308).

The tenant, the user and the agent come from the token and from nothing else: not from a header,
not from the request body. A token that cannot be turned into a complete principal is refused.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from keystone.core.types import Principal
from keystone.identity.jwt import AuthError, Forbidden, Reason

if TYPE_CHECKING:
    from keystone.settings import AgentConfig

TENANT_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
# Only these two realm roles mean something to Keystone. Others (Keycloak's own default roles,
# for one) are dropped.
KEPT_ROLES = frozenset({"admin", "approver"})
TENANT_GROUP_PREFIX = "tenants"


def principal_from_claims(
    claims: Mapping[str, Any],
    agents: Mapping[str, AgentConfig],
    *,
    allow_unknown_agents: bool = False,
) -> Principal:
    """The principal for a token's claims.

    `agents` is the `agents` section of the config. An agent that is not in it is refused with
    Forbidden (HTTP 403), or let in with trust `low` when `allow_unknown_agents` is true.
    """
    tenant = _tenant(claims)
    user_id = claims.get("sub")
    if not isinstance(user_id, str) or not user_id:
        raise AuthError(Reason.INVALID_CLAIM, "sub")
    agent_id = _agent(claims)
    if agent_id in agents:
        trust = agents[agent_id].trust
    elif allow_unknown_agents:
        trust = "low"
    else:
        raise Forbidden(Reason.UNKNOWN_AGENT)
    return Principal(
        tenant_id=tenant,
        user_id=user_id,
        groups=_groups(claims.get("groups")),
        agent_id=agent_id,
        agent_trust=trust,
        scopes=_scopes(claims.get("scope")),
        roles=_roles(claims),
    )


def _tenant(claims: Mapping[str, Any]) -> str:
    tenant = claims.get("tenant")
    if tenant is None or tenant == "":
        raise AuthError(Reason.MISSING_TENANT)
    if not isinstance(tenant, str) or not TENANT_ID.fullmatch(tenant):
        raise AuthError(Reason.INVALID_TENANT)
    return tenant


def _agent(claims: Mapping[str, Any]) -> str:
    """`azp` names the client the token was issued to. Some identity providers send `client_id`
    instead."""
    agent = claims.get("azp") or claims.get("client_id")
    if not isinstance(agent, str) or not agent:
        raise AuthError(Reason.MISSING_AGENT)
    return agent


def _strings(raw: object, claim: str) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise AuthError(Reason.INVALID_CLAIM, claim)
    return list(raw)


def _groups(raw: object) -> tuple[str, ...]:
    """Group paths as Keycloak sends them (`/support`, `/tenants/acme`) become plain names. The
    tenant groups are dropped: the tenant has its own claim."""
    if raw is None:
        return ()
    names = []
    for path in _strings(raw, "groups"):
        name = path.removeprefix("/")
        if name and name != TENANT_GROUP_PREFIX and not name.startswith(f"{TENANT_GROUP_PREFIX}/"):
            names.append(name)
    return tuple(dict.fromkeys(names))


def _roles(claims: Mapping[str, Any]) -> tuple[str, ...]:
    """The `roles` claim, or Keycloak's `realm_access.roles` when there is none, kept to the
    roles Keystone knows."""
    raw = claims.get("roles")
    if raw is None:
        realm_access = claims.get("realm_access")
        raw = realm_access.get("roles") if isinstance(realm_access, dict) else None
    if raw is None:
        return ()
    return tuple(sorted(KEPT_ROLES.intersection(_strings(raw, "roles"))))


def _scopes(raw: object) -> tuple[str, ...]:
    return tuple(raw.split()) if isinstance(raw, str) else ()
