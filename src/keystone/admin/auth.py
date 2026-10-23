"""Who may use the admin API (KS-403): a caller with the `admin` role.

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


class AdminRefused(Exception):
    """The caller may not use the admin API. `response` is the answer to send."""

    def __init__(self, response: Response) -> None:
        super().__init__(f"admin request refused with {response.status_code}")
        self.response = response


class AdminAuth:
    """A FastAPI dependency: `Depends(admin_auth)` gives the principal, or refuses the request."""

    def __init__(self, authenticator: Authenticator, role: str = ADMIN_ROLE) -> None:
        self.authenticator = authenticator
        self.role = role

    async def __call__(self, request: Request) -> Principal:
        try:
            principal = await self.authenticator.admin_principal(request.headers)
        except AuthError as error:
            raise AdminRefused(auth_refusal(request, error, self.authenticator.settings)) from None
        if self.role not in principal.roles:
            log.info("admin_refused", user=principal.user_id, reason="role_required")
            raise AdminRefused(
                JSONResponse(
                    {"error": "forbidden", "reason": f"the {self.role} role is required"},
                    status_code=403,
                )
            )
        return principal


async def admin_refused_handler(_request: Request, exc: Exception) -> Response:
    if isinstance(exc, AdminRefused):
        return exc.response
    raise exc
