"""OAuth protected resource metadata (RFC 9728): how a client learns whom to sign in with.

A 401 from /mcp points at this document. An MCP client that speaks OAuth reads it, finds the
authorization server, and can sign the user in without the identity provider being hard-coded.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.requests import Request

from keystone.settings import Settings

METADATA_PATH = "/.well-known/oauth-protected-resource"
# The Host header is checked against the allowed hosts, but a pattern such as `localhost:*`
# matches any text after the colon. Only a plain host and port go into a URL or a header.
_HOST = re.compile(r"[A-Za-z0-9.-]+(:\d{1,5})?|\[[0-9A-Fa-f:.]+\](:\d{1,5})?")


def public_origin(request: Request, configured: str | None) -> str:
    """The address clients use to reach Keystone: `public_base_url` when it is set, otherwise the
    address this request came in on."""
    if configured:
        return configured
    host = request.headers.get("host", "")
    scheme = "https" if request.scope.get("scheme") == "https" else "http"
    return f"{scheme}://{host if _HOST.fullmatch(host) else 'localhost'}"


def metadata_url(origin: str) -> str:
    return f"{origin}{METADATA_PATH}"


def protected_resource_metadata(origin: str, issuer: str) -> dict[str, Any]:
    return {
        "resource": f"{origin}/mcp",
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
    }


def add_metadata_route(app: FastAPI, settings: Settings) -> None:
    @app.get(METADATA_PATH)
    async def protected_resource(request: Request) -> JSONResponse:
        if settings.auth.mode == "none" or not settings.oidc_issuer:
            return JSONResponse({"error": "no authorization server is configured"}, 404)
        origin = public_origin(request, settings.public_base_url)
        return JSONResponse(protected_resource_metadata(origin, settings.oidc_issuer))
