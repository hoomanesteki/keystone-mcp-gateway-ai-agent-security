"""Who may use the admin API (KS-403): a caller with the `admin` role. The routes under
`/approvals` also let an approver in (KS-604), and nothing else does.

The token is validated by the same code as the MCP endpoint (`Authenticator`), so the two cannot
disagree about who is signed in. The refusals use the same words too: 401 with a pointer to the
sign-in metadata, 403, and 503 when the identity provider's keys cannot be fetched.
"""

from __future__ import annotations

import structlog
from fastapi import Request
from starlette.responses import JSONResponse, Response

from keystone.core.types import Principal
from keystone.identity.jwt import AuthError
from keystone.identity.middleware import Authenticator, auth_refusal

log = structlog.get_logger()

ADMIN_ROLE = "admin"
APPROVER_ROLE = "approver"
# A route whose path is this one or below it also accepts the approver role. Every other route
# needs the admin role, so a route added later is for admins only until it is listed here.
APPROVER_PATH = "/approvals"


class AdminRefused(Exception):
    """The caller may not use the admin API. `response` is the answer to send."""

    def __init__(self, response: Response) -> None:
        super().__init__(f"admin request refused with {response.status_code}")
        self.response = response


class AdminAuth:
    """A FastAPI dependency: `Depends(admin_auth)` gives the principal, or refuses the request."""

    def __init__(
        self,
        authenticator: Authenticator,
        role: str = ADMIN_ROLE,
        approver_role: str = APPROVER_ROLE,
    ) -> None:
        self.authenticator = authenticator
        self.role = role
        self.approver_role = approver_role

    def roles_for(self, request: Request) -> tuple[str, ...]:
        """The roles that may call the route this request matched, the approver role first when
        the route is an approvals route."""
        route = request.scope.get("route")
        path = str(getattr(route, "path", ""))
        if path == APPROVER_PATH or path.startswith(f"{APPROVER_PATH}/"):
            return (self.approver_role, self.role)
        return (self.role,)

    async def __call__(self, request: Request) -> Principal:
        try:
            principal = await self.authenticator.admin_principal(request.headers)
        except AuthError as error:
            raise AdminRefused(auth_refusal(request, error, self.authenticator.settings)) from None
        allowed = self.roles_for(request)
        if not set(allowed).intersection(principal.roles):
            log.info("admin_refused", user=principal.user_id, reason="role_required")
            raise AdminRefused(
                JSONResponse(
                    {
                        "error": "forbidden",
                        "reason": f"the {' or '.join(allowed)} role is required",
                    },
                    status_code=403,
                )
            )
        return principal


async def admin_refused_handler(_request: Request, exc: Exception) -> Response:
    if isinstance(exc, AdminRefused):
        return exc.response
    raise exc
