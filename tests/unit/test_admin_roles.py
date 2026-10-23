"""KS-604: which roles may call which admin route."""

from types import SimpleNamespace

import pytest
from starlette.requests import Request

from keystone.admin.auth import AdminAuth

pytestmark = pytest.mark.phase(6)


def request_for(path: str | None) -> Request:
    scope: dict[str, object] = {"type": "http", "method": "GET", "headers": []}
    if path is not None:
        scope["route"] = SimpleNamespace(path=path)
    return Request(scope)


@pytest.mark.parametrize(
    "path", ["/approvals", "/approvals/{approval_id}", "/approvals/{approval_id}/decision"]
)
def test_the_approvals_routes_take_an_approver_and_an_admin(path: str) -> None:
    auth = AdminAuth(None)  # type: ignore[arg-type]

    assert auth.roles_for(request_for(path)) == ("approver", "admin")


@pytest.mark.parametrize(
    "path",
    [
        "/audit",
        "/audit/{seq}",
        "/tools/{name}/approve-change",
        "/policies/reload",
        "/sessions",
        # Names that merely start like the approvals path are not it.
        "/approvals-export",
        "/approvalsx",
        "",
        None,
    ],
)
def test_every_other_route_takes_an_admin_only(path: str | None) -> None:
    auth = AdminAuth(None)  # type: ignore[arg-type]

    assert auth.roles_for(request_for(path)) == ("admin",)
