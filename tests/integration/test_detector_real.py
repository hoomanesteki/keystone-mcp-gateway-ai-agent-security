"""KS-707: the parts of the detector evaluation that need the network and the real model.

The unit tests of `eval/` run on fakes and on the synthetic parts. Here the two public datasets are
downloaded for real, into a folder of the test, and checked against the committed manifest, and the
real classifier scores a few texts of each kind next to the rules. Marked slow like the other
real-model test (test_classifier_real.py): CI skips it, and the phase gate runs it after installing
both extras.

    uv sync --extra scanner --extra eval && uv run pytest tests/integration/test_detector_real.py
"""

import asyncio
import json
from pathlib import Path
from typing import Literal

import pytest

from eval.detector.datasets import Dataset, Sample, build, load_manifest
from eval.detector.run import evaluate, score_rules, score_with_model
from keystone.settings import ScannerSettings

pytestmark = [pytest.mark.phase(7), pytest.mark.slow]

MODEL: Literal["protectai-deberta-v2"] = "protectai-deberta-v2"
PER_KIND = 4


@pytest.fixture(scope="module")
def downloaded(tmp_path_factory: pytest.TempPathFactory) -> tuple[Dataset, Path]:
    """The dataset built with the public parts fetched from Hugging Face, once for the module."""
    cache = tmp_path_factory.mktemp("detector-data")
    return build(download=True, cache=cache), cache


def test_the_public_parts_download_and_agree_with_the_manifest(
    downloaded: tuple[Dataset, Path],
) -> None:
    data, cache = downloaded
    manifest = load_manifest()
    assert manifest is not None

    # `build` raises when a text differs from the manifest, so a dataset here is the one measured.
    assert data.complete, f"{data.notes}: run `uv sync --extra eval` and check the network"
    assert {s.id: s.label for s in data.samples} == {
        e["id"]: e["label"] for e in manifest["samples"]
    }
    assert dict(data.parts) == manifest["counts"]
    assert (cache / "deepset--prompt-injections.jsonl").is_file()
    assert (cache / "Salesforce--wikitext.jsonl").is_file()


def test_a_second_build_reads_the_cache_and_needs_no_network(
    downloaded: tuple[Dataset, Path],
) -> None:
    data, cache = downloaded

    def refuse(url: str) -> bytes:
        raise AssertionError(f"went to the network for {url}")

    again = build(download=True, cache=cache, fetch=refuse)

    assert again.complete, again.notes
    assert [s.id for s in again.samples] == [s.id for s in data.samples]


def a_few_of_each(data: Dataset) -> list[Sample]:
    """The first texts by id of the kinds that a report tells apart, on the dev split."""
    chosen: list[Sample] = []
    for kind, label in (
        ("indirect", 1),
        ("negative", 0),
        ("hard_negative", 0),
        ("public", 1),
        ("public", 0),
    ):
        found = [s for s in data.split("dev") if (s.kind, s.label) == (kind, label)]
        assert len(found) >= PER_KIND, (kind, label)
        chosen += sorted(found, key=lambda s: s.id)[:PER_KIND]
    return chosen


def test_the_real_model_scores_each_kind_of_text_next_to_the_rules(
    downloaded: tuple[Dataset, Path],
) -> None:
    data, _ = downloaded
    picked = a_few_of_each(data)
    settings = ScannerSettings(classifier=MODEL, classifier_timeout_ms=10_000)

    scored = asyncio.run(score_with_model(picked, settings))
    rules_alone = score_rules(picked, settings.model_copy(update={"classifier": "none"}))

    assert [item.sample.id for item in scored] == [s.id for s in picked]
    for item in scored:
        # Every text got a score from the model: none timed out or failed.
        assert item.model == MODEL, (item.sample.id, item.model)
        assert item.classifier is not None and 0.0 <= item.classifier <= 1.0
        assert item.combined == pytest.approx(max(item.rules, item.classifier))
        assert item.scan_ms is not None and item.scan_ms > 0
    # The rules score is the same with or without the model next to it.
    assert [item.rules for item in scored] == pytest.approx([item.rules for item in rules_alone])
    # A set of texts this small cannot say how good the model is, but the numbers must come out.
    result = evaluate(scored, ("rules", "classifier", "combined"), 0.5, 0.85)
    assert set(result) == {"rules", "classifier", "combined", "combined_300ms"}
    assert json.loads(json.dumps(result)) == result
