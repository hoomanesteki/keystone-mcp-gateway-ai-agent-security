"""KS-902: the compose override and the script that sets the three configs of the red team.

Nothing here starts a container. The override is read as the data it is, its variables are fed to
`Settings` the way compose would hand them to Keystone, and the copy of `policies/` that makes C1 is
made by the same two shell lines the script runs.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from keystone.policy.store import load_policies
from keystone.settings import Settings

pytestmark = [pytest.mark.phase(9), pytest.mark.usefixtures("clean_env")]

ROOT = Path(__file__).resolve().parents[2]
OVERRIDE = yaml.safe_load((ROOT / "deploy" / "redteam.override.yml").read_text())
BASE = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text())
SCRIPT = (ROOT / "scripts" / "redteam.sh").read_text()
CONFIG = ROOT / "deploy" / "keystone.compose.yaml"
RULE_OF_TWO = {"rule-of-two", "tainted-external-effect", "deny-critical-when-tainted"}
SETTINGS = OVERRIDE["services"]["keystone"]["environment"]


def default_of(value: str) -> str:
    """`${NAME:-default}` is `default`."""
    found = re.fullmatch(r"\$\{[A-Z_]+:-(.*)\}", value)
    assert found, value
    return found.group(1)


def variable_of(value: str) -> str:
    found = re.match(r"\$\{([A-Z_]+):-", value)
    assert found, value
    return found.group(1)


def settings_with(monkeypatch: pytest.MonkeyPatch, **given: str) -> Settings:
    """Keystone as compose starts it: the config file, and the variables of the override set to
    `given` where it names them and to their defaults elsewhere."""
    monkeypatch.setenv("KEYSTONE_CONFIG", str(CONFIG))
    for name, value in SETTINGS.items():
        if name.startswith("KEYSTONE_"):
            monkeypatch.setenv(name, given.get(variable_of(value), default_of(value)))
    return Settings()


def test_the_override_changes_nothing_when_no_variable_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KEYSTONE_CONFIG", str(CONFIG))
    plain = Settings()

    with_defaults = settings_with(monkeypatch)

    assert with_defaults.model_dump() == plain.model_dump()
    assert with_defaults.profile == "full" and with_defaults.scanner.enabled is True


def test_the_variables_of_c0_make_a_passthrough_gateway_that_does_not_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = settings_with(monkeypatch, REDTEAM_PROFILE="passthrough", REDTEAM_SCANNER="false")

    assert settings.profile == "passthrough" and settings.scanner.enabled is False


def test_the_variable_of_c1_turns_the_scanner_off_and_leaves_the_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = settings_with(monkeypatch, REDTEAM_SCANNER="false")

    assert settings.profile == "full" and settings.scanner.enabled is False


def test_the_variables_of_a_real_model_point_the_proxy_at_the_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = settings_with(
        monkeypatch,
        REDTEAM_LLM_BASE_URL="https://api.anthropic.com",
        REDTEAM_LLM_KEY_ENV="ANTHROPIC_API_KEY",
    )

    assert settings.llm_proxy.anthropic.base_url == "https://api.anthropic.com"
    assert settings.llm_proxy.anthropic.api_key_env == "ANTHROPIC_API_KEY"
    # The other provider is not touched.
    assert settings.llm_proxy.openai.base_url == "http://fake-llm:8199"


MOUNT = re.compile(r"^\$\{(?P<variable>[A-Z_]+):-(?P<default>[^}]*)\}:(?P<target>/[^:]+):ro$")


def test_the_mounts_replace_the_ones_of_the_stack_and_do_not_add_to_them() -> None:
    base = BASE["services"]["keystone"]["volumes"]
    over = [MOUNT.fullmatch(m) for m in OVERRIDE["services"]["keystone"]["volumes"]]
    assert all(over)
    mounts = [m for m in over if m]

    # Compose merges mounts by their target, so each of these takes the place of one in the base.
    from_base = {m.split(":")[1]: m.split(":")[0] for m in base if m.count(":") >= 1}
    wanted = {"/etc/keystone/keystone.yaml", "/etc/keystone/policies", "/etc/keystone/pricing.yaml"}
    assert {m["target"] for m in mounts} == wanted
    assert wanted <= set(from_base)
    # With no variable set, each mounts what the base mounts.
    for mount in mounts:
        assert mount["default"] == from_base[mount["target"]], mount.string


def test_the_script_uses_the_variables_the_override_reads_and_no_others() -> None:
    declared = {
        variable_of(value) if value.startswith("${") else value
        for value in [*SETTINGS.values(), *OVERRIDE["services"]["keystone"]["volumes"]]
        if "${REDTEAM_" in value
    }
    # The key of a real provider is passed through under its own name.
    declared |= {"ANTHROPIC_API_KEY"}
    used = set(re.findall(r"\b(REDTEAM_[A-Z_]+)\b", SCRIPT))

    assert used <= declared | {"REDTEAM_PRICING"}
    assert {v for v in declared if v.startswith("REDTEAM_")} <= used | {"REDTEAM_CONFIG"}
    assert "REDTEAM_CONFIG" in used  # set by --config-ref


def test_the_script_is_valid_bash_and_executable() -> None:
    path = ROOT / "scripts" / "redteam.sh"

    assert subprocess.run(["bash", "-n", str(path)], check=False).returncode == 0
    assert path.stat().st_mode & 0o111


def test_the_script_refuses_a_real_model_without_its_key_before_it_touches_the_stack() -> None:
    env = {"PATH": "/usr/bin:/bin"}
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "redteam.sh"), "llm", "--model", "a-model"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 2
    assert "not run: needs an API key" in result.stderr


def test_c1_is_the_policies_without_the_rule_of_two_and_nothing_else(tmp_path: Path) -> None:
    # The lines of scripts/redteam.sh that make the copy, run on the policies of the repository.
    assert "cp -R policies/." in SCRIPT and "-name rule_of_two.cedar -delete" in SCRIPT
    copy = tmp_path / "policies-c1"
    shutil.copytree(ROOT / "policies", copy)
    for path in copy.rglob("rule_of_two.cedar"):
        path.unlink()

    full = {p.id for p in load_policies(ROOT / "policies", ("acme",), include_demo=True).policies}
    c1 = {p.id for p in load_policies(copy, ("acme",), include_demo=True).policies}

    assert full >= RULE_OF_TWO and not RULE_OF_TWO & c1
    assert full - c1 == RULE_OF_TWO  # nothing else was lost
    assert c1 >= {"external-email-needs-approval", "approve-transfer-over-500"}
