"""The admin API (`/admin/api/v1`). Every route needs the `admin` role.

Only the policy reload exists so far. The read endpoints, tool review and the audit search arrive
with Phase 5 (KS-507), on the same router and the same auth.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from starlette.responses import JSONResponse, Response

from keystone.admin.auth import AdminAuth
from keystone.policy.store import PolicyStore

PREFIX = "/admin/api/v1"


def create_admin_router(admin: AdminAuth, policies: PolicyStore) -> APIRouter:
    # On the router, so a route added later cannot forget the check.
    router = APIRouter(prefix=PREFIX, tags=["admin"], dependencies=[Depends(admin)])

    @router.post("/policies/reload")
    async def reload_policies() -> Response:
        """Read the policy files again. A set with any problem is refused with 422, every problem
        named, and the set in force stays in force."""
        result = await policies.reload()
        if result.ok:
            return JSONResponse(
                {
                    "version": result.version,
                    "previous": result.previous,
                    "changed": result.changed,
                }
            )
        return JSONResponse(
            {
                "error": "invalid_policies",
                "errors": list(result.errors),
                "version": result.version,
            },
            status_code=422,
        )

    return router
