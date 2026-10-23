"""KS-306: the credential slot adds headers just before the dispatch and drops them after."""

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from keystone.audit.sink import InMemoryAuditSink
from keystone.core.errors import Code, Reject
from keystone.core.types import CallContext, ToolResult
from keystone.gateway.dispatch import UpstreamDispatcher
from keystone.gateway.interceptors.credentials import CredentialInterceptor
from keystone.gateway.wiring import PipelineDeps, build_pipeline
from keystone.identity.vault import Cipher, Vault
from keystone.settings import Settings
from tests.fixtures.calls import OLIVIA, make_ctx, make_tool
from tests.fixtures.vault import MemoryCredentialStore

KEY = "mail-api-key-4d1e0b7a9c"
MODES = {"mail": ("acme", "static"), "crm": ("acme", "per_user"), "echo": ("acme", "none")}


async def vault_with_mail_key() -> Vault:
    vault = Vault(Cipher(Fernet.generate_key().decode()), MemoryCredentialStore(dict(MODES)))
    await vault.set("acme", "mail", {"X-Api-Key": KEY})
    return vault


@pytest.mark.phase(3)
async def test_the_slot_puts_the_upstreams_headers_on_the_context() -> None:
    interceptor = CredentialInterceptor(await vault_with_mail_key())
    ctx = make_ctx(tool=make_tool("mail", "read_email"))

    await interceptor.before_call(ctx)

    assert isinstance(ctx.upstream_headers["X-Api-Key"], SecretStr)
    assert ctx.upstream_headers["X-Api-Key"].get_secret_value() == KEY
    assert KEY not in ctx.model_dump_json() and KEY not in repr(ctx)


@pytest.mark.phase(3)
async def test_headers_are_dropped_after_the_call() -> None:
    interceptor = CredentialInterceptor(await vault_with_mail_key())
    ctx = make_ctx(tool=make_tool("mail", "read_email"))
    await interceptor.before_call(ctx)

    await interceptor.after_call(ctx)

    assert ctx.upstream_headers == {}


@pytest.mark.phase(3)
async def test_an_upstream_with_no_credential_mode_gets_no_headers() -> None:
    interceptor = CredentialInterceptor(await vault_with_mail_key())
    ctx = make_ctx(tool=make_tool("echo", "echo"))

    await interceptor.before_call(ctx)

    assert ctx.upstream_headers == {}


@pytest.mark.phase(3)
async def test_without_a_vault_there_is_nothing_to_add() -> None:
    ctx = make_ctx(tool=make_tool("echo", "echo"))

    await CredentialInterceptor(None).before_call(ctx)

    assert ctx.upstream_headers == {}


@pytest.mark.phase(3)
async def test_a_user_without_a_credential_is_refused_by_name_of_the_upstream() -> None:
    interceptor = CredentialInterceptor(await vault_with_mail_key())
    ctx = make_ctx(tool=make_tool("crm", "lookup"))

    with pytest.raises(Reject) as raised:
        await interceptor.before_call(ctx)

    assert raised.value.code is Code.DENIED
    assert raised.value.message == "no credential for this user on crm"
    assert ctx.upstream_headers == {}


@pytest.mark.phase(3)
async def test_the_vault_is_asked_for_the_tools_tenant_and_the_callers_user() -> None:
    asked: list[tuple[str, str, str | None]] = []

    class Spy:
        async def headers_for(
            self, tenant_id: str, upstream_id: str, user_id: str | None
        ) -> dict[str, SecretStr]:
            asked.append((tenant_id, upstream_id, user_id))
            return {}

    ctx = make_ctx(tool=make_tool("mail", "read_email"))

    await CredentialInterceptor(Spy()).before_call(ctx)  # type: ignore[arg-type]

    assert asked == [("acme", "mail", OLIVIA.user_id)]


class SeesTheHeaders:
    """A dispatcher that notes the headers it was given at the moment of the call."""

    def __init__(self) -> None:
        self.seen: dict[str, str] = {}

    async def dispatch(self, ctx: CallContext) -> ToolResult:
        self.seen = {name: value.get_secret_value() for name, value in ctx.upstream_headers.items()}
        return ToolResult(content=[{"type": "text", "text": "ok"}])


@pytest.mark.phase(3)
async def test_in_the_pipeline_the_dispatcher_sees_the_headers_and_nothing_remains_after() -> None:
    dispatcher = SeesTheHeaders()
    pipeline = build_pipeline(
        Settings(env="test", auth={"mode": "none"}),  # type: ignore[arg-type]
        PipelineDeps(dispatcher, InMemoryAuditSink(), vault=await vault_with_mail_key()),
    )
    ctx = make_ctx(tool=make_tool("mail", "read_email", schema={"type": "object"}), arguments={})

    result = await pipeline.run(ctx)

    assert not result.is_error
    assert dispatcher.seen == {"X-Api-Key": KEY}
    assert ctx.upstream_headers == {}


@pytest.mark.phase(3)
async def test_a_call_refused_before_the_credential_slot_never_opens_the_vault() -> None:
    opened: list[str] = []

    class Counting:
        async def headers_for(
            self, tenant_id: str, upstream_id: str, user_id: str | None
        ) -> dict[str, SecretStr]:
            opened.append(upstream_id)
            return {}

    class Refuses:
        name = "policy"

        async def before_call(self, ctx: CallContext) -> None:
            raise Reject(Code.DENIED, "not today")

        async def after_call(self, ctx: CallContext) -> None:
            return None

    pipeline = build_pipeline(
        Settings(env="test", auth={"mode": "none"}),  # type: ignore[arg-type]
        PipelineDeps(SeesTheHeaders(), InMemoryAuditSink(), vault=Counting()),  # type: ignore[arg-type]
        {"policy": Refuses()},
    )
    ctx = make_ctx(tool=make_tool("mail", "read_email", schema={"type": "object"}), arguments={})

    result = await pipeline.run(ctx)

    assert result.is_error
    assert opened == []


@pytest.mark.phase(3)
async def test_the_dispatcher_drops_the_headers_even_when_the_call_fails() -> None:
    class FailingPool:
        @asynccontextmanager
        async def lease(
            self, upstream_id: str, headers: Mapping[str, SecretStr] | None = None
        ) -> AsyncIterator[None]:
            raise RuntimeError("connection refused")
            yield  # pragma: no cover - makes this a generator

    ctx = make_ctx(tool=make_tool("mail", "read_email"))
    ctx.upstream_headers = {"X-Api-Key": SecretStr(KEY)}

    with pytest.raises(RuntimeError):
        await UpstreamDispatcher(FailingPool()).dispatch(ctx)  # type: ignore[arg-type]

    assert ctx.upstream_headers == {}
