"""KS-308: an agent the config does not list is refused after its token has been validated."""

from pathlib import Path

import pytest

from keystone.identity.jwt import Forbidden, TokenValidator
from keystone.identity.principals import principal_from_claims
from keystone.settings import Settings
from tests.fixtures.fake_idp import FakeIdp

CONFIG = "agents:\n  support-agent: {trust: standard}\n  ops-agent: {trust: high}\n"


@pytest.mark.phase(3)
async def test_unknown_agent_rejected(fake_idp: FakeIdp, tmp_path: Path, clean_env: None) -> None:
    path = tmp_path / "keystone.yaml"
    path.write_text(CONFIG)
    settings = Settings(config_path=path)
    validator = TokenValidator(fake_idp.issuer, "keystone")

    # The token is sound: signed by the IdP, for this audience. Only the agent is unknown.
    claims = await validator.validate(fake_idp.token_for("alice", agent="rogue-agent"))
    with pytest.raises(Forbidden) as raised:
        principal_from_claims(
            claims, settings.agents, allow_unknown_agents=settings.auth.allow_unknown_agents
        )

    assert raised.value.status == 403
    assert raised.value.reason == "unknown_agent"


@pytest.mark.phase(3)
async def test_ops_agent_has_trust_high_for_olivia(
    fake_idp: FakeIdp, tmp_path: Path, clean_env: None
) -> None:
    path = tmp_path / "keystone.yaml"
    path.write_text(CONFIG)
    settings = Settings(config_path=path)
    validator = TokenValidator(fake_idp.issuer, "keystone")

    claims = await validator.validate(fake_idp.token_for("olivia", agent="ops-agent"))
    principal = principal_from_claims(claims, settings.agents)

    assert (principal.user_id, principal.agent_id, principal.agent_trust) == (
        "olivia",
        "ops-agent",
        "high",
    )
    assert principal.groups == ("operators",)
