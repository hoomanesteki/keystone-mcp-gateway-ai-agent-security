"""KS-701: the scanner section of the settings."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from keystone.settings import ScannerSettings, Settings

pytestmark = pytest.mark.phase(7)


def test_the_defaults_are_the_plans() -> None:
    config = ScannerSettings()

    assert config.enabled is True
    assert (config.thresholds.suspicious, config.thresholds.injection) == (0.5, 0.85)
    assert config.allowed_domains == []
    assert config.max_scan_chars == 200_000


def test_the_settings_carry_a_scanner_section(settings: Settings) -> None:
    assert settings.scanner == ScannerSettings()


def test_a_yaml_file_sets_the_scanner(tmp_path: Path, clean_env: None) -> None:
    path = tmp_path / "keystone.yaml"
    path.write_text(
        "scanner:\n"
        "  thresholds: {suspicious: 0.4, injection: 0.7}\n"
        "  allowed_domains: [cdn.acme.test]\n"
    )

    config = Settings(config_path=path).scanner

    assert (config.thresholds.suspicious, config.thresholds.injection) == (0.4, 0.7)
    assert config.allowed_domains == ["cdn.acme.test"]


def test_an_environment_variable_beats_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    path = tmp_path / "keystone.yaml"
    path.write_text("scanner:\n  thresholds: {suspicious: 0.4, injection: 0.7}\n")
    monkeypatch.setenv("KEYSTONE_SCANNER__THRESHOLDS__INJECTION", "0.95")

    assert Settings(config_path=path).scanner.thresholds.injection == 0.95


@pytest.mark.parametrize(
    "bad",
    [
        {"thresholds": {"suspicious": 0.9, "injection": 0.5}},
        {"thresholds": {"suspicious": -0.1}},
        {"thresholds": {"injection": 1.5}},
        {"thresholds": {"medium": 0.5}},
        {"max_scan_chars": 10},
        {"allowed_domains": ["https://cdn.acme.test/path"]},
        {"allowed_domains": [""]},
        {"unknown": True},
    ],
)
def test_a_setting_that_makes_no_sense_is_refused(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ScannerSettings.model_validate(bad)


def test_allowed_domains_are_kept_in_lower_case_without_a_leading_dot() -> None:
    config = ScannerSettings(allowed_domains=["CDN.Acme.test", ".docs.acme.test"])

    assert config.allowed_domains == ["cdn.acme.test", "docs.acme.test"]


def test_the_classifier_defaults_are_the_plans() -> None:
    config = ScannerSettings()

    assert config.classifier == "protectai-deberta-v2"
    assert config.classifier_timeout_ms == 300


@pytest.mark.parametrize(
    "bad",
    [
        {"classifier": "a-model-nobody-listed"},
        {"classifier": ""},
        {"classifier_timeout_ms": 0},
        {"classifier_timeout_ms": 60_000},
    ],
)
def test_a_classifier_setting_that_makes_no_sense_is_refused(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ScannerSettings.model_validate(bad)


@pytest.mark.parametrize("name", ["protectai-deberta-v2", "prompt-guard-2-86m", "none"])
def test_every_classifier_the_plan_names_is_accepted(name: str) -> None:
    assert ScannerSettings.model_validate({"classifier": name}).classifier == name


def test_one_underscore_turns_the_classifier_off(
    monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    monkeypatch.setenv("KEYSTONE_SCANNER_CLASSIFIER", "none")

    assert Settings().scanner.classifier == "none"


def test_the_nested_name_does_the_same(monkeypatch: pytest.MonkeyPatch, clean_env: None) -> None:
    monkeypatch.setenv("KEYSTONE_SCANNER__CLASSIFIER", "none")

    assert Settings().scanner.classifier == "none"


def test_the_short_name_wins_over_the_nested_one_and_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    path = tmp_path / "keystone.yaml"
    path.write_text("scanner:\n  classifier: prompt-guard-2-86m\n")
    monkeypatch.setenv("KEYSTONE_SCANNER__CLASSIFIER", "prompt-guard-2-86m")
    monkeypatch.setenv("KEYSTONE_SCANNER_CLASSIFIER", "none")

    config = Settings(config_path=path).scanner

    assert config.classifier == "none"


def test_the_short_name_keeps_the_rest_of_the_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    path = tmp_path / "keystone.yaml"
    path.write_text("scanner:\n  thresholds: {suspicious: 0.4, injection: 0.7}\n")
    monkeypatch.setenv("KEYSTONE_SCANNER_CLASSIFIER", "none")

    config = Settings(config_path=path).scanner

    assert config.classifier == "none" and config.thresholds.injection == 0.7


def test_a_short_name_that_is_not_a_classifier_is_refused(
    monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    monkeypatch.setenv("KEYSTONE_SCANNER_CLASSIFIER", "gpt")

    with pytest.raises(ValidationError):
        Settings()


def test_the_default_actions_follow_the_risk_of_the_tool() -> None:
    assert ScannerSettings().actions.model_dump() == {
        "low": "annotate",
        "medium": "annotate",
        "high": "redact",
        "critical": "block",
    }


def test_an_action_can_be_changed_for_one_risk(tmp_path: Path, clean_env: None) -> None:
    path = tmp_path / "keystone.yaml"
    path.write_text("scanner:\n  actions: {high: block}\n")

    config = Settings(config_path=path).scanner

    assert config.actions.high == "block" and config.actions.low == "annotate"
