#!/usr/bin/env python3
"""Write the admin API's OpenAPI schema without starting Keystone.

    dump_openapi.py [OUT]

OUT is a file, or `-` (the default) for standard output. `make console-types` writes
`console/openapi.json` with this and turns it into `console/src/api/schema.d.ts`. The console job
of CI does the same and fails when the committed types differ, so the console cannot drift from
the API.

The schema comes from the app object: the routes and the models, nothing else. No database,
identity provider or server is needed, which is why the stand-ins below can be empty. It is the
document that the running gateway serves at /admin/api/v1/openapi.json, and a test compares the
two.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from keystone.admin.api import PREFIX, AdminDeps, create_admin_app
from keystone.admin.auth import AdminAuth

# The console's origin only matters to the CORS middleware at request time.
CONSOLE_ORIGIN = "http://localhost:5173"


def admin_schema() -> dict[str, Any]:
    """The schema as the gateway serves it: the app's own, plus the `servers` entry that FastAPI
    adds from the prefix the app is mounted under."""
    nothing: Any = None
    app = create_admin_app(
        AdminDeps(
            auth=AdminAuth(nothing),
            sessions=nothing,
            tools=nothing,
            policies=nothing,
            console_origin=CONSOLE_ORIGIN,
        )
    )
    schema: dict[str, Any] = dict(app.openapi())
    schema["servers"] = [{"url": PREFIX}, *schema.get("servers", [])]
    return schema


def render(schema: dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("out", nargs="?", default="-", help="a file, or - for standard output")
    args = parser.parse_args(argv)

    text = render(admin_schema())
    if args.out == "-":
        sys.stdout.write(text)
    else:
        Path(args.out).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
