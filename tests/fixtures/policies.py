"""Policy trees for tests: the real schema and pack, or small files a test writes itself."""

import shutil
from collections.abc import Mapping
from pathlib import Path

import httpx2

ROOT = Path(__file__).resolve().parents[2]
POLICY_ROOT = ROOT / "policies"
SCHEMA_TEXT = (POLICY_ROOT / "schema.cedarschema").read_text()


def write_policies(
    root: Path, files: Mapping[str, str] | None = None, *, schema: str | None = SCHEMA_TEXT
) -> Path:
    """Write `files` (relative path to text) under `root`, and the real schema unless told not
    to. Returns `root`."""
    root.mkdir(parents=True, exist_ok=True)
    if schema is not None:
        (root / "schema.cedarschema").write_text(schema)
    for relative, text in (files or {}).items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return root


def permit(name: str, condition: str = "true", scope: str = "principal, action, resource") -> str:
    return f'@id("{name}")\npermit ({scope}) when {{ {condition} }};\n'


def forbid(name: str, condition: str = "true", scope: str = "principal, action, resource") -> str:
    return f'@id("{name}")\nforbid ({scope}) when {{ {condition} }};\n'


def copy_pack(destination: Path) -> Path:
    """A copy of the repository's policies that a test may edit."""
    target = destination / "policies"
    shutil.copytree(POLICY_ROOT, target)
    return target


def reload_policies(base_url: str, token: str | None) -> httpx2.Response:
    """Ask a running app to reload its policies, as the admin API does for the CLI."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx2.post(f"{base_url}/admin/api/v1/policies/reload", headers=headers, timeout=30)
