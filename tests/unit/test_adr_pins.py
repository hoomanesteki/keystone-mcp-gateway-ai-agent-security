import re
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ADR = (ROOT / "docs" / "adr" / "0002-dependency-pins.md").read_text()


def adr_rows(*sections: str) -> dict[str, str]:
    """First two cells of every table row in the named sections: name or image, then version."""
    rows: dict[str, str] = {}
    current = ""
    for line in ADR.splitlines():
        if line.startswith("## "):
            current = line[3:]
        if not current.startswith(sections) or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 2 and not set(cells[0]) <= {"-", " "}:
            rows[cells[0]] = cells[1]
    return rows


def normalise(spec: str) -> str:
    return re.split(r"[<>=!~\[ ;]", spec, maxsplit=1)[0].lower().replace("_", "-")


def image_references() -> set[tuple[str, str]]:
    refs: set[tuple[str, str]] = set()
    compose = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text())
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    images = [svc["image"] for svc in compose["services"].values()]
    images += [
        svc["image"] for job in ci["jobs"].values() for svc in job.get("services", {}).values()
    ]
    dockerfile = (ROOT / "Dockerfile").read_text()
    images += re.findall(r"^FROM (\S+)", dockerfile, flags=re.MULTILINE)
    # `COPY --from=build` names a stage, not an image.
    images += [ref for ref in re.findall(r"--from=(\S+)", dockerfile) if ":" in ref]
    for image in images:
        name, _, tag = image.rpartition(":")
        refs.add((name.removeprefix("docker.io/library/"), tag))
    return refs


@pytest.mark.phase(0)
def test_every_direct_dependency_is_listed_with_its_locked_version() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    locked = {package["name"]: package["version"] for package in lock["package"]}
    direct = {normalise(d) for d in pyproject["project"]["dependencies"]}
    direct |= {normalise(d) for d in pyproject["dependency-groups"]["dev"]}
    rows = adr_rows("Python packages")

    assert {name: rows.get(name) for name in direct} == {name: locked[name] for name in direct}


@pytest.mark.phase(0)
def test_every_image_is_pinned_and_listed() -> None:
    rows = adr_rows("Container images")
    references = image_references()

    assert references, "no images found"
    for name, tag in sorted(references):
        assert tag and tag != "latest", f"{name} is not pinned"
        assert rows.get(name) == tag, f"{name}:{tag} is missing from ADR-0002"
