"""KS-405: an extractor the schema cannot honor stops startup, with the upstream, tool and key."""

import pytest
from pydantic import SecretStr

from keystone.app import create_app
from keystone.registry.config import ConfigError, ToolOverride, UpstreamConfig
from keystone.settings import Settings, TenantConfig

pytestmark = [pytest.mark.phase(4), pytest.mark.services]


def settings_with(tools: dict[str, ToolOverride], database_url: str, redis_url: str) -> Settings:
    return Settings(
        env="test",
        database_url=SecretStr(database_url),
        redis_url=SecretStr(redis_url),
        tenants=[TenantConfig(id="acme", name="Acme Corp")],
        allow_private_upstreams=True,
        oidc_issuer="http://idp.test/realms/keystone",
        upstreams=[
            UpstreamConfig(id="mail", tenant="acme", url="http://127.0.0.1:1/mcp", tools=tools)
        ],
    )


@pytest.mark.parametrize(
    ("extract", "fragment"),
    [
        ({"to": "$.to"}, "extract key 'to' is not an argument the policies can read"),
        ({"amount": "$.to | domain"}, "produces text but the schema's amount is a Long"),
        ({"recipient_domain": "$.to | nope"}, "unknown pipe nope"),
    ],
)
async def test_an_extractor_the_schema_cannot_honor_stops_startup(
    clean_env: None,
    test_database_url: str,
    test_redis_url: str,
    clean_db: None,
    extract: dict[str, str],
    fragment: str,
) -> None:
    tools = {"send_email": ToolOverride(extract=extract)}
    app = create_app(settings_with(tools, test_database_url, test_redis_url))

    with pytest.raises(ConfigError) as raised:
        async with app.router.lifespan_context(app):
            pass

    assert "upstream 'mail' tool 'send_email'" in str(raised.value)
    assert fragment in str(raised.value)


async def test_the_extractors_in_the_example_config_are_accepted(
    clean_env: None, test_database_url: str, test_redis_url: str, clean_db: None
) -> None:
    tools = {
        "send_email": ToolOverride(extract={"recipient_domain": "$.to | domain"}),
        "transfer": ToolOverride(extract={"amount": "$.amount | cents"}),
    }
    app = create_app(settings_with(tools, test_database_url, test_redis_url))

    # The upstream is not there, which is reported and does not stop startup. The extractors are
    # checked before anything else is written.
    async with app.router.lifespan_context(app):
        pass
