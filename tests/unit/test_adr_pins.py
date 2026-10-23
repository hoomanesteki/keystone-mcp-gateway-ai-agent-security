import json
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


@pytest.mark.phase(6)
def test_every_console_package_is_listed_with_its_exact_version() -> None:
    package = json.loads((ROOT / "console" / "package.json").read_text())
    direct = {**package["dependencies"], **package["devDependencies"]}

    assert all(re.fullmatch(r"\d+\.\d+\.\d+", version) for version in direct.values()), direct
    listed = dict(adr_rows("Console packages"))
    listed.pop("Package")  # the header row of each table
    assert listed == direct


@pytest.mark.phase(6)
def test_the_console_node_and_pnpm_versions_are_listed() -> None:
    rows = adr_rows("Console toolchain")
    package = json.loads((ROOT / "console" / "package.json").read_text())

    assert rows["Node.js"] == (ROOT / "console" / ".nvmrc").read_text().strip()
    assert package["packageManager"] == f"pnpm@{rows['pnpm']}"


@pytest.mark.phase(6)
def test_every_workflow_action_is_listed_with_its_version() -> None:
    rows = adr_rows("CI actions")
    used: set[tuple[str, str]] = set()
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        for name, _, version in re.findall(
            r"uses:\s*([\w.-]+/[\w.-]+)(@)(\S+)", workflow.read_text(), flags=re.MULTILINE
        ):
            used.add((name, version))

    assert used, "no actions found"
    for name, version in sorted(used):
        assert rows.get(name) == version, f"{name}@{version} is missing from ADR-0002"


@pytest.mark.phase(7)
def test_every_scanner_extra_package_is_listed_with_its_locked_version() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    extra = {normalise(d) for d in pyproject["project"]["optional-dependencies"]["scanner"]}
    # torch is locked twice: the ordinary wheel, and the CPU wheel for Linux ("2.14.1+cpu").
    locked: dict[str, set[str]] = {}
    for package in lock["package"]:
        locked.setdefault(package["name"], set()).add(package["version"].split("+")[0])
    rows = adr_rows("Python packages: the scanner extra")

    assert set(rows) - {"Package"} == extra
    assert {name: {rows[name]} for name in extra} == {name: locked[name] for name in extra}


@pytest.mark.phase(7)
def test_every_eval_extra_package_is_listed_with_its_locked_version() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    extra = {normalise(d) for d in pyproject["project"]["optional-dependencies"]["eval"]}
    locked = {package["name"]: package["version"] for package in lock["package"]}
    rows = adr_rows("Python packages: the eval extra")

    assert set(rows) - {"Package"} == extra
    assert {name: rows[name] for name in extra} == {name: locked[name] for name in extra}
