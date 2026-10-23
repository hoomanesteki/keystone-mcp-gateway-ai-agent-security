"""KS-708: the web upstream and the poison flags are wired into the compose stack."""

from pathlib import Path

import pytest
import yaml

from tests.fixtures.keystone import demo_tools

pytestmark = pytest.mark.phase(7)

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text())
KEYSTONE = yaml.safe_load((ROOT / "deploy" / "keystone.compose.yaml").read_text())


def test_the_web_upstream_runs_on_8105_with_a_key_and_a_health_check() -> None:
    web = COMPOSE["services"]["web-mcp"]

    assert web["command"][:1] == ["examples.upstreams.web_server"]
    assert web["command"][-2:] == ["--port", "8105"]
    assert web["ports"] == ["${WEB_PORT:-8105}:8105"]
    assert "WEB_API_KEY" in web["environment"]
    assert "8105/healthz" in " ".join(web["healthcheck"]["test"])
    assert COMPOSE["services"]["keystone"]["depends_on"]["web-mcp"] == {
        "condition": "service_healthy"
    }


def test_keystone_serves_the_web_upstream_to_acme_and_tags_fetch_untrusted_and_low_risk() -> None:
    [web] = [u for u in KEYSTONE["upstreams"] if u["id"] == "web"]

    assert web["tenant"] == "acme" and web["url"] == "http://web-mcp:8105/mcp"
    assert web["credential_env"] == {"X-Api-Key": "WEB_API_KEY"}
    fetch = demo_tools("web")["fetch"]
    assert fetch.risk is not None and fetch.risk.value == "low"
    assert fetch.tags is not None and [tag.value for tag in fetch.tags] == ["reads_untrusted"]


def test_the_demo_stack_serves_the_poisoned_mailbox_and_files() -> None:
    assert COMPOSE["services"]["mail-mcp"]["environment"]["MAIL_POISONED"] == "1"
    assert COMPOSE["services"]["files-mcp"]["environment"]["FILES_POISONED"] == "1"
    # The other tenant's drive is not part of the demo.
    assert "FILES_POISONED" not in COMPOSE["services"]["files-globex-mcp"]["environment"]
