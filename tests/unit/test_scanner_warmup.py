"""KS-704: the model loads when the gateway starts, and a model that will not load costs nothing.

`warm_up` is what the app's start-up runs in the background (ADR-0011). A classifier that is not a
Hugging Face model has nothing to load. One that cannot be loaded is logged once; each scan then
reports `model: "error"` and the rules decide.
"""

import anyio
import pytest
import structlog

from keystone.defense.classifier import ClassifierUnavailable, FakeClassifier, warm_up

pytestmark = pytest.mark.phase(7)


class Warmable(FakeClassifier):
    def __init__(self, error: BaseException | None = None) -> None:
        super().__init__(lambda text: 0.0, name="warmable")
        self.error = error
        self.warmed = 0

    async def warm(self) -> None:
        self.warmed += 1
        if self.error is not None:
            raise self.error


async def test_a_model_is_loaded_and_the_log_says_so() -> None:
    classifier = Warmable()

    with structlog.testing.capture_logs() as logs:
        await warm_up(classifier)

    assert classifier.warmed == 1
    assert [e["event"] for e in logs] == ["scanner_classifier_ready"]
    assert logs[0]["classifier"] == "warmable"


async def test_the_gateway_is_told_the_name_of_the_model_once_it_has_loaded() -> None:
    told: list[str] = []

    await warm_up(Warmable(), told.append)

    assert told == ["warmable"]


async def test_a_model_that_cannot_be_loaded_is_never_announced() -> None:
    told: list[str] = []

    await warm_up(Warmable(ClassifierUnavailable("needs the scanner extra")), told.append)

    assert told == []


async def test_a_classifier_with_nothing_to_load_is_left_alone() -> None:
    with structlog.testing.capture_logs() as logs:
        await warm_up(FakeClassifier(lambda text: 0.0))

    assert logs == []


async def test_a_model_that_cannot_be_loaded_is_logged_and_does_not_stop_the_gateway() -> None:
    classifier = Warmable(ClassifierUnavailable("needs the scanner extra"))

    with structlog.testing.capture_logs() as logs:
        await warm_up(classifier)

    [entry] = logs
    assert entry["event"] == "scanner_classifier_not_ready" and entry["log_level"] == "error"
    assert entry["error"] == "ClassifierUnavailable"
    # The reason is in the exception's own log line; the text of it is not repeated here.
    assert "scanner extra" not in str(entry)


async def test_cancellation_while_loading_is_not_swallowed() -> None:
    cancelled = anyio.get_cancelled_exc_class()

    with pytest.raises(cancelled):
        await warm_up(Warmable(cancelled()))
