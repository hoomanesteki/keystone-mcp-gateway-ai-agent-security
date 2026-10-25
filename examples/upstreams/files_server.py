"""Demo files server. Every path is relative to one workspace directory and cannot leave it."""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from examples.upstreams._common import (
    FIXTURES,
    CallLog,
    Database,
    register_test_routes,
    run_cli,
    variant_folders,
)

MAX_BYTES = 1024 * 1024
SCHEMA = "CREATE TABLE writes (seq INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT, content TEXT)"


def create_server(
    workspace: Path | None = None,
    db_path: Path | None = None,
    seed: Path | None = None,
    poisoned: bool | None = None,
) -> MCPServer:
    """Build the server. The workspace defaults to FILES_WORKSPACE, then to a temp directory. The
    files it starts with, and goes back to on reset, come from `seed`, then FILES_SEED, then
    examples/fixtures/files. A second server with another seed plays another tenant's drive.
    `poisoned` adds two files that carry an instruction for the agent that reads them (KS-708).
    It defaults to the FILES_POISONED=1 environment flag."""
    if poisoned is None:
        poisoned = os.environ.get("FILES_POISONED") == "1"
    seed_dir = seed or (Path(os.environ["FILES_SEED"]) if os.environ.get("FILES_SEED") else None)
    seed_dir = seed_dir or FIXTURES / "files"
    env_workspace = os.environ.get("FILES_WORKSPACE")
    base = workspace or (Path(env_workspace) if env_workspace else None)
    root = (base or Path(tempfile.mkdtemp(prefix="keystone-files-"))).resolve()
    env_path = os.environ.get("FILES_DB")
    db = Database(db_path or (Path(env_path) if env_path else None), "files")
    log = CallLog()

    def reset(variant: str | None = None) -> None:
        # A variant is the seed with the files of its folders over it, and it does not take the
        # poisoned flag (KS-901).
        folders = variant_folders(variant)
        if root.exists():
            shutil.rmtree(root)
        shutil.copytree(seed_dir, root)
        if poisoned and variant is None:
            shutil.copytree(FIXTURES / "injections" / "files", root, dirs_exist_ok=True)
        for folder in folders:
            if (overlay := folder / "files").is_dir():
                shutil.copytree(overlay, root, dirs_exist_ok=True)
        db.path.unlink(missing_ok=True)
        log.calls.clear()
        with db.connect() as con:
            con.execute(SCHEMA)

    def state() -> dict[str, Any]:
        with db.connect() as con:
            rows = con.execute("SELECT path, content FROM writes ORDER BY seq").fetchall()
        return {
            "written": [{"path": r["path"], "content": r["content"]} for r in rows],
            "calls": list(log.calls),
        }

    def inside(relative: str) -> Path:
        """Resolve a path under the workspace, or refuse. Symlinks are followed before the check."""
        if os.path.isabs(relative) or "\x00" in relative:
            raise ToolError("path must be relative to the workspace")
        target = (root / relative).resolve()
        if not target.is_relative_to(root):
            raise ToolError("path is outside the workspace")
        return target

    reset()
    server = MCPServer("files", log_level="WARNING", middleware=[log])

    @server.tool()
    def list_files(path: str = ".") -> list[dict[str, Any]]:
        """List the files and folders in a workspace folder."""
        folder = inside(path)
        if not folder.is_dir():
            raise ToolError(f"{path!r} is not a folder")
        return [
            {
                "name": entry.name,
                "type": "folder" if entry.is_dir() else "file",
                "size": entry.stat().st_size if entry.is_file() else None,
            }
            for entry in sorted(folder.iterdir(), key=lambda e: e.name)
        ]

    @server.tool()
    def read_file(path: str) -> str:
        """Read a text file from the workspace."""
        target = inside(path)
        if not target.is_file():
            raise ToolError(f"{path!r} is not a file")
        if target.stat().st_size > MAX_BYTES:
            raise ToolError("file is larger than 1 MB")
        try:
            return target.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise ToolError(f"{path!r} is not a text file") from None

    @server.tool()
    def write_file(path: str, content: str) -> dict[str, Any]:
        """Write a text file in the workspace, replacing it if it exists."""
        target = inside(path)
        data = content.encode("utf-8")
        if len(data) > MAX_BYTES:
            raise ToolError("content is larger than 1 MB")
        if target == root or target.is_dir():
            raise ToolError(f"{path!r} is a folder")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        try:
            with db.connect() as con:
                con.execute(
                    "INSERT INTO writes (path, content) VALUES (?, ?)",
                    (str(target.relative_to(root)), content),
                )
        except sqlite3.Error as exc:
            raise ToolError("could not record the write") from exc
        return {"path": str(target.relative_to(root)), "bytes": len(data)}

    register_test_routes(server, reset, state, variants=True)
    return server


def main(argv: list[str] | None = None) -> None:
    run_cli("files", 8102, create_server, argv)


if __name__ == "__main__":
    main()
