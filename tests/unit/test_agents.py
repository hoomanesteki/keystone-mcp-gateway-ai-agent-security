"""KS-308: the agents section of the config, the trust it gives, and `keystone agent list`."""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from keystone.admin.cli import app
from keystone.identity.jwt import Forbidden
from keystone.identity.principals import principal_from_claims
from keystone.settings import Settings

CONFIG = """
agents:
  support-agent: {trust: standard}
  ops-agent: {trust: high}
"""
runner = CliRunner()


def settings_from(tmp_path: Path, text: str = CONFIG, **options: Any) -> Settings:
    path = tmp_path / "keystone.yaml"
    path.write_text(text)
    return Settings(config_path=path, **options)


def claims(agent: str) -> dict[str, Any]:
    return {"sub": "olivia", "tenant": "acme", "azp": agent, "groups": ["/operators"]}


@pytest.mark.phase(3)
def test_agent_trust_from_config(tmp_path: Path, clean_env: None) -> None:
    settings = settings_from(tmp_path)

    ops = principal_from_claims(claims("ops-agent"), settings.agents)
    support = principal_from_claims(claims("support-agent"), settings.agents)

    assert ops.agent_trust == "high"
    assert support.agent_trust == "standard"


@pytest.mark.phase(3)
def test_an_agent_without_a_trust_level_is_standard(tmp_path: Path, clean_env: None) -> None:
    settings = settings_from(tmp_path, "agents:\n  helper: {}\n")

    assert settings.agents["helper"].trust == "standard"


@pytest.mark.phase(3)
def test_an_unknown_agent_is_forbidden_unless_the_config_allows_it(
    tmp_path: Path, clean_env: None
) -> None:
    settings = settings_from(tmp_path)

    with pytest.raises(Forbidden) as raised:
        principal_from_claims(claims("rogue-agent"), settings.agents)
    allowed = principal_from_claims(
        claims("rogue-agent"), settings.agents, allow_unknown_agents=True
    )
    known_when_allowed = principal_from_claims(
        claims("ops-agent"), settings.agents, allow_unknown_agents=True
    )

    assert (raised.value.reason, raised.value.status) == ("unknown_agent", 403)
    assert allowed.agent_trust == "low"
    assert known_when_allowed.agent_trust == "high"  # a listed agent keeps its own level


@pytest.mark.phase(3)
def test_allow_unknown_agents_defaults_to_off_and_has_an_env_switch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    assert Settings().auth.allow_unknown_agents is False

    monkeypatch.setenv("KEYSTONE_AUTH__ALLOW_UNKNOWN_AGENTS", "true")

    assert Settings().auth.allow_unknown_agents is True


@pytest.mark.phase(3)
@pytest.mark.parametrize(
    "text",
    ["agents:\n  a: {trust: root}\n", "agents:\n  a: {trsut: high}\n", "auth: {allow: yes}\n"],
)
def test_a_misspelled_or_unknown_value_is_an_error(
    tmp_path: Path, clean_env: None, text: str
) -> None:
    with pytest.raises(ValueError, match=r"trust|trsut|allow"):
        settings_from(tmp_path, text)


@pytest.mark.phase(3)
def test_agent_list_prints_each_agent_with_its_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    path = tmp_path / "keystone.yaml"
    path.write_text(CONFIG)
    monkeypatch.setenv("KEYSTONE_CONFIG", str(path))

    result = runner.invoke(app, ["agent", "list"])

    assert result.exit_code == 0, result.output
    rows = [line.split() for line in result.output.splitlines()]
    assert rows[0] == ["AGENT", "TRUST"]
    assert rows[1:3] == [["ops-agent", "high"], ["support-agent", "standard"]]
    assert "unknown agents: refused (403)" in result.output


@pytest.mark.phase(3)
def test_agent_list_says_what_happens_to_an_unknown_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    path = tmp_path / "keystone.yaml"
    path.write_text(CONFIG + "auth: {allow_unknown_agents: true}\n")
    monkeypatch.setenv("KEYSTONE_CONFIG", str(path))

    result = runner.invoke(app, ["agent", "list", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "agents": [
            {"id": "ops-agent", "trust": "high"},
            {"id": "support-agent", "trust": "standard"},
        ],
        "unknown_agents": "allowed with trust low",
    }


@pytest.mark.phase(3)
def test_agent_list_with_no_agents_says_so(clean_env: None) -> None:
    result = runner.invoke(app, ["agent", "list"])

    assert result.exit_code == 0
    assert "no agents configured" in result.output
    assert "unknown agents: refused (403)" in result.output
