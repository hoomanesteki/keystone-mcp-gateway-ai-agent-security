"""KS-704: the app loads the scanner's model in the background when it starts, outside the tests.

The app asks for the model at start, so the first scans of a call do not find it still loading
(3 to 13 seconds) and fall back to the rules. The tests of the suite run with `env=test`, which
leaves the model alone: hundreds of apps start in a run of the tests, and none wants 700 MB.
"""

import threading
from collections.abc import Callable

import pytest

from keystone.defense.classifier import FakeClassifier
from keystone.settings import ScannerSettings
from tests.fixtures.keystone import KeystoneApp

pytestmark = [pytest.mark.phase(7), pytest.mark.services]

WAIT_S = 10.0
Factory = Callable[..., KeystoneApp]


class Spy(FakeClassifier):
    def __init__(self) -> None:
        super().__init__(lambda text: 0.0, name="spy")
        self.warmed = threading.Event()

    async def warm(self) -> None:
        self.warmed.set()


def start(factory: Factory, spy: Spy, monkeypatch: pytest.MonkeyPatch, **settings: object) -> None:
    monkeypatch.setattr("keystone.app.load_classifier", lambda cfg: spy)
    app = factory(
        settings={"scanner": ScannerSettings(classifier="protectai-deberta-v2"), **settings}
    )
    assert app.thread.server.started


def test_a_gateway_that_is_not_under_test_loads_the_model_when_it_starts(
    keystone_app_factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = Spy()

    start(keystone_app_factory, spy, monkeypatch, env="dev")

    assert spy.warmed.wait(WAIT_S)


def test_a_gateway_under_test_leaves_the_model_alone(
    keystone_app_factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = Spy()

    start(keystone_app_factory, spy, monkeypatch)  # env=test

    assert not spy.warmed.wait(1.0)


def test_a_gateway_with_the_scanner_off_asks_for_no_model(
    keystone_app_factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[object] = []
    monkeypatch.setattr("keystone.app.load_classifier", lambda cfg: asked.append(cfg))

    keystone_app_factory(settings={"env": "dev", "scanner": ScannerSettings(enabled=False)})

    assert asked == []
