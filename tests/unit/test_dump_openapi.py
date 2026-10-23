"""KS-605: the admin API's schema can be written without a server, for the console's types."""

import json
from pathlib import Path

import dump_openapi
import pytest

pytestmark = pytest.mark.phase(6)


def test_the_schema_describes_every_admin_route() -> None:
    schema = dump_openapi.admin_schema()

    assert schema["openapi"].startswith("3.")
    assert schema["servers"] == [{"url": "/admin/api/v1"}]
    assert set(schema["paths"]) >= {
        "/audit",
        "/audit/verify",
        "/audit/{seq}",
        "/tools",
        "/tools/{name}",
        "/tools/{name}/approve-change",
        "/approvals",
        "/approvals/{approval_id}",
        "/approvals/{approval_id}/decision",
    }
    assert {"ApprovalItem", "ApprovalDetail", "DecisionBody", "ErrorBody"} <= set(
        schema["components"]["schemas"]
    )


def test_the_output_does_not_change_between_runs() -> None:
    """The console job compares generated types with the committed ones, so the schema they are
    made from must come out the same every time."""
    assert dump_openapi.render(dump_openapi.admin_schema()) == dump_openapi.render(
        dump_openapi.admin_schema()
    )


def test_main_writes_a_file_or_standard_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "openapi.json"

    assert dump_openapi.main([str(target)]) == 0
    assert dump_openapi.main(["-"]) == 0

    written = target.read_text(encoding="utf-8")
    assert json.loads(written)["info"]["title"] == "Keystone admin API"
    assert capsys.readouterr().out == written
