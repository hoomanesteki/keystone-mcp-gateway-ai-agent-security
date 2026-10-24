"""Demo web server: `fetch(url)` returns a stored page. It never reaches the network.

The pages are in examples/fixtures/web/pages.json, and some of them carry an instruction for the
agent that reads them (KS-708). A url is looked up as it is written, except that the fragment and
surrounding space are ignored. A url with no page is an error result, so an agent that is told to
open an address of the attacker's gets nothing, and `GET /_state` lists every url that was asked
for, with whether a page was stored. That list is how a test sees that an agent tried.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from examples.upstreams._common import (
    FIXTURES,
    CallLog,
    register_test_routes,
    run_cli,
    variant_folders,
)

MAX_URL_CHARS = 2048
# /_state keeps the start of a long url and no more than this many of them.
SHOWN_URL_CHARS = 300
MAX_FETCHED = 1000


def lookup_key(url: str) -> str:
    return url.strip().split("#", 1)[0]


def load_pages(variant: str | None = None) -> dict[str, dict[str, Any]]:
    """The stored pages by lookup key: the seed's, then the pages the folders of a variant add or
    replace (`web.json`, KS-901)."""
    folders = variant_folders(variant)
    pages = {
        lookup_key(page["url"]): page
        for page in json.loads((FIXTURES / "web" / "pages.json").read_text())
    }
    for folder in folders:
        if (overlay := folder / "web.json").is_file():
            for page in json.loads(overlay.read_text()):
                pages[lookup_key(page["url"])] = page
    return pages


def create_server() -> MCPServer:
    pages = load_pages()
    log = CallLog()
    fetched: list[dict[str, Any]] = []

    def reset(variant: str | None = None) -> None:
        stored = load_pages(variant)  # raises for an unknown variant before anything is cleared
        pages.clear()
        pages.update(stored)
        log.calls.clear()
        fetched.clear()

    def state() -> dict[str, Any]:
        return {"fetched": list(fetched), "calls": list(log.calls)}

    server = MCPServer("web", log_level="WARNING", middleware=[log])

    @server.tool()
    def fetch(url: str) -> dict[str, Any]:
        """Fetch a web page and return its title and text."""
        if len(url) > MAX_URL_CHARS:
            raise ToolError(f"the url is longer than {MAX_URL_CHARS} characters")
        page = pages.get(lookup_key(url))
        if len(fetched) < MAX_FETCHED:
            fetched.append({"url": lookup_key(url)[:SHOWN_URL_CHARS], "found": page is not None})
        if page is None:
            raise ToolError(f"no page is stored for {lookup_key(url)[:SHOWN_URL_CHARS]!r}")
        return {
            "url": page["url"],
            "status": 200,
            "title": page["title"],
            "text": page["text"],
        }

    register_test_routes(server, reset, state, variants=True)
    return server


def main(argv: list[str] | None = None) -> None:
    run_cli("web", 8105, create_server, argv)


if __name__ == "__main__":
    main()
