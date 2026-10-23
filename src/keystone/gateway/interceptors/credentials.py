"""The credential slot: upstream credentials are added at the last moment (KS-306).

It runs after policy and approval, so a call that is refused never has its credential decrypted.
The headers go on the context as SecretStr, the dispatcher hands the plain values to the pool for
the one call, and they are dropped again afterwards. Nothing about a credential reaches the agent:
not the tool list, not a result, not a rejection.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import SecretStr

from keystone.core.types import CallContext
from keystone.registry.naming import is_virtual


class HeaderSource(Protocol):
    async def headers_for(
        self, tenant_id: str, upstream_id: str, user_id: str | None
    ) -> dict[str, SecretStr]: ...


class CredentialInterceptor:
    name = "credential"

    def __init__(self, vault: HeaderSource | None) -> None:
        self._vault = vault

    async def before_call(self, ctx: CallContext) -> None:
        if self._vault is None or is_virtual(ctx.tool):
            ctx.upstream_headers = {}
            return
        # A per_user upstream with no credential for this user raises Reject(DENIED) here.
        ctx.upstream_headers = await self._vault.headers_for(
            ctx.tool.tenant_id, ctx.tool.upstream_id, ctx.principal.user_id
        )

    async def after_call(self, ctx: CallContext) -> None:
        ctx.upstream_headers = {}
