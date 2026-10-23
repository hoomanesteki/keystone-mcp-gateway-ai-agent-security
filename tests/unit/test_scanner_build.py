"""KS-702: the classifier is an extra.

CI never installs it and never downloads a model. The compose stack builds with it, and the image
pre-downloads the model and then never goes to the network for it.
"""

import re
import tomllib
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.phase(7)

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))


def test_the_extra_is_torch_and_transformers() -> None:
    names = {
        re.split(r"[<>=!~\[ ;]", spec, maxsplit=1)[0]
        for spec in PYPROJECT["project"]["optional-dependencies"]["scanner"]
    }

    assert names == {"torch", "transformers"}
    # Nothing the gateway needs on its own depends on them.
    runtime = " ".join(PYPROJECT["project"]["dependencies"])
    assert "torch" not in runtime and "transformers" not in runtime


def test_linux_gets_the_cpu_wheels_and_the_lock_holds_no_cuda_libraries() -> None:
    uv = PYPROJECT["tool"]["uv"]

    assert uv["sources"]["torch"] == [{"index": "pytorch-cpu", "marker": "sys_platform == 'linux'"}]
    [index] = uv["index"]
    assert index["name"] == "pytorch-cpu" and index["url"].endswith("/whl/cpu")
    assert index["explicit"] is True
    lock = (ROOT / "uv.lock").read_text()
    assert 'name = "nvidia' not in lock and 'name = "triton"' not in lock


def test_the_dockerfile_installs_the_extra_and_the_model_only_when_asked() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()

    assert re.search(r"^ARG WITH_SCANNER=0$", dockerfile, flags=re.MULTILINE)
    assert "--extra scanner" in dockerfile
    assert "keystone.defense.classifier fetch" in dockerfile
    # The model is in the image, so the container never goes to the network for it.
    assert "HF_HUB_OFFLINE=1" in dockerfile
    assert "HF_HOME=" in dockerfile


def test_the_model_download_stays_in_a_build_cache_so_an_edit_does_not_fetch_it_again() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    joined = re.sub(r"\\\n\s*", " ", dockerfile).splitlines()
    [step] = [line for line in joined if line.startswith("RUN ") and "classifier fetch" in line]

    cache = re.match(r"RUN --mount=type=cache,target=(\S+) ", step)
    assert cache, "the step that fetches the model has no cache mount"
    # The download goes to the cache, and the files of the pinned revision are copied into the
    # image as files (-L): the links in the cache point into a store of blobs outside the folder
    # of the model, and a copy of the folder alone would leave the weights behind.
    assert f"HF_HOME={cache.group(1)}" in step
    assert "cp -aL" in step and "/opt/hf-cache/hub/" in step


def test_compose_builds_keystone_with_the_scanner() -> None:
    compose = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text())

    assert compose["services"]["keystone"]["build"]["args"] == {"WITH_SCANNER": "1"}


def test_the_upstreams_image_has_no_scanner() -> None:
    dockerfile = (ROOT / "deploy" / "Dockerfile.upstreams").read_text()

    assert "scanner" not in dockerfile.lower()


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_ci_never_installs_the_extra_or_builds_the_image_with_it(workflow: Path) -> None:
    text = workflow.read_text()

    assert "--extra scanner" not in text and "--all-extras" not in text
    assert "WITH_SCANNER" not in text


def test_ci_builds_the_image_without_a_build_argument() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

    assert "docker build -t keystone:ci ." in text


def test_the_phase_7_gate_installs_the_extra_so_the_model_test_can_run() -> None:
    makefile = (ROOT / "Makefile").read_text()
    gate = makefile[makefile.index("\ngate:") :].split("\n\n", 1)[0]

    assert "--extra scanner" in gate
