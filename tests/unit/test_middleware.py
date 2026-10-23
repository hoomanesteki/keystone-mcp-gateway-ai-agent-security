"""KS-304: the pieces of the authentication middleware that need no server."""

import pytest
from starlette.datastructures import Headers
from starlette.requests import Request

from keystone.app import create_app
from keystone.core.types import Principal
from keystone.identity.jwt import AuthError
from keystone.identity.metadata import metadata_url, protected_resource_metadata, public_origin
from keystone.identity.middleware import (
    AuthConfigError,
    Authenticator,
    SessionBindings,
    Verdict,
    bearer_token,
    check_auth_settings,
)
from keystone.settings import Settings

ALICE = Principal(tenant_id="acme", user_id="alice", agent_id="support-agent")
ISSUER = "https://idp.test/realms/keystone"


def headers(*values: str) -> Headers:
    return Headers(raw=[(b"authorization", value.encode()) for value in values])


def request_with(host: str | None, scheme: str = "http") -> Request:
    raw = [(b"host", host.encode())] if host is not None else []
    scope = {"type": "http", "scheme": scheme, "path": "/", "headers": raw, "query_string": b""}
    return Request(scope)


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    ("value", "token"),
    [
        ("Bearer abc.def.ghi", "abc.def.ghi"),
        ("bearer abc.def.ghi", "abc.def.ghi"),
        ("BEARER   abc-_~+/=", "abc-_~+/="),
    ],
)
def test_a_bearer_header_yields_its_token(value: str, token: str) -> None:
    assert bearer_token(headers(value)) == token


@pytest.mark.phase(3)
def test_no_authorization_header_means_no_credentials() -> None:
    with pytest.raises(AuthError) as raised:
        bearer_token(Headers(raw=[]))

    assert raised.value.reason == "no_credentials"


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    "values",
    [("Basic abc",), ("Bearer",), ("Bearer a b",), ("Bearer a;b",), ("Bearer a", "Bearer b")],
)
def test_anything_else_is_malformed(values: tuple[str, ...]) -> None:
    with pytest.raises(AuthError) as raised:
        bearer_token(headers(*values))

    assert raised.value.reason == "malformed"


@pytest.mark.phase(3)
def test_a_binding_compares_tenant_user_and_agent_and_nothing_else() -> None:
    bindings = SessionBindings()
    bindings.bind("s1", ALICE)

    assert bindings.verdict("s1", ALICE) is Verdict.SAME
    # Groups, roles and trust may change between tokens without ending the session.
    promoted = ALICE.model_copy(update={"groups": ("operators",), "roles": ("admin",)})
    assert bindings.verdict("s1", promoted) is Verdict.SAME
    for changed in (
        {"tenant_id": "globex"},
        {"user_id": "bob"},
        {"agent_id": "ops-agent"},
    ):
        assert bindings.verdict("s1", ALICE.model_copy(update=changed)) is Verdict.DIFFERENT
    assert bindings.verdict("never-opened", ALICE) is Verdict.UNKNOWN


@pytest.mark.phase(3)
def test_a_forgotten_session_is_unknown_and_the_table_is_bounded() -> None:
    bindings = SessionBindings(max_sessions=2)
    for name in ("s1", "s2", "s3"):
        bindings.bind(name, ALICE)

    assert bindings.verdict("s1", ALICE) is Verdict.UNKNOWN  # the oldest was dropped
    bindings.forget("s2")
    assert bindings.verdict("s2", ALICE) is Verdict.UNKNOWN
    assert bindings.verdict("s3", ALICE) is Verdict.SAME


@pytest.mark.phase(3)
def test_a_binding_that_is_used_is_the_last_to_go() -> None:
    bindings = SessionBindings(max_sessions=2)
    bindings.bind("s1", ALICE)
    bindings.bind("s2", ALICE)
    bindings.verdict("s1", ALICE)  # s1 was used after s2 was bound

    bindings.bind("s3", ALICE)

    assert bindings.verdict("s2", ALICE) is Verdict.UNKNOWN
    assert bindings.verdict("s1", ALICE) is Verdict.SAME


@pytest.mark.phase(3)
def test_oidc_needs_an_issuer() -> None:
    with pytest.raises(AuthConfigError, match="oidc_issuer"):
        check_auth_settings(Settings(env="test"))
    check_auth_settings(Settings(env="test", oidc_issuer=ISSUER))
    check_auth_settings(Settings(env="test", auth={"mode": "none"}))  # type: ignore[arg-type]


@pytest.mark.phase(3)
def test_prod_needs_https_for_every_address() -> None:
    check_auth_settings(Settings(env="prod", oidc_issuer=ISSUER))

    with pytest.raises(AuthConfigError) as raised:
        check_auth_settings(
            Settings(
                env="prod",
                oidc_issuer="http://idp.test/realms/keystone",
                oidc_discovery_url="http://keycloak:8080/realms/keystone/.well-known/x",
                public_base_url="http://keystone.test",
            )
        )

    for name in ("oidc_issuer", "oidc_discovery_url", "public_base_url"):
        assert name in str(raised.value)


@pytest.mark.phase(3)
def test_an_app_is_not_built_with_authentication_that_cannot_work() -> None:
    with pytest.raises(AuthConfigError, match="oidc_issuer"):
        create_app(Settings(env="test"))


@pytest.mark.phase(3)
async def test_without_authentication_everybody_is_the_dev_principal() -> None:
    settings = Settings(env="test", auth={"mode": "none"})  # type: ignore[arg-type]

    principal = await Authenticator(settings).principal(Headers(raw=[]))

    assert principal == settings.dev_principal
    assert principal.user_id == "olivia"


@pytest.mark.phase(3)
def test_the_origin_is_the_configured_address_or_the_one_the_request_used() -> None:
    assert public_origin(request_with("127.0.0.1:8080"), None) == "http://127.0.0.1:8080"
    assert public_origin(request_with("keystone:8080", "https"), None) == "https://keystone:8080"
    assert public_origin(request_with("[::1]:8080"), None) == "http://[::1]:8080"
    assert public_origin(request_with("x"), "https://keystone.example.test") == (
        "https://keystone.example.test"
    )


@pytest.mark.phase(3)
@pytest.mark.parametrize("host", ['localhost:1"; x="', "evil.test\r\nx: y", "a b", "", None])
def test_a_host_header_that_is_not_a_host_never_reaches_a_header(host: str | None) -> None:
    assert public_origin(request_with(host), None) == "http://localhost"


@pytest.mark.phase(3)
def test_the_metadata_document_names_the_resource_and_the_issuer() -> None:
    assert metadata_url("https://k.test") == "https://k.test/.well-known/oauth-protected-resource"
    assert protected_resource_metadata("https://k.test", ISSUER) == {
        "resource": "https://k.test/mcp",
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
    }
