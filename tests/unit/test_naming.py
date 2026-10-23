import pytest

from keystone.registry.naming import (
    check_upstream_id,
    is_reserved,
    make_tool_name,
    split_tool_name,
)


@pytest.mark.phase(1)
@pytest.mark.parametrize(
    ("upstream", "tool"),
    [
        ("mail", "read_email"),
        ("bank", "get_balance"),
        ("files_globex", "write-file"),
        ("echo", "_leading_underscore"),
        ("echo", "has__double"),
        ("a1", "X"),
    ],
)
def test_tool_name_roundtrip(upstream: str, tool: str) -> None:
    name = make_tool_name(upstream, tool)

    assert name == f"{upstream}__{tool}"
    assert split_tool_name(name) == (upstream, tool)


@pytest.mark.phase(1)
@pytest.mark.parametrize(
    ("upstream", "tool"),
    [
        ("mail", "read.email"),
        ("mail", "read email"),
        ("mail", "read/email"),
        ("mail", ""),
        ("mail", "x" * 60),
        ("mail", "é"),
    ],
)
def test_tool_name_rejects_invalid(upstream: str, tool: str) -> None:
    with pytest.raises(ValueError, match="tool name"):
        make_tool_name(upstream, tool)


@pytest.mark.phase(1)
def test_name_of_exactly_64_characters_is_accepted() -> None:
    tool = "t" * (64 - len("mail__"))

    assert len(make_tool_name("mail", tool)) == 64


@pytest.mark.phase(1)
@pytest.mark.parametrize(
    "upstream",
    ["", "m", "Mail", "1mail", "ma-il", "ma__il", "mail_", "mail__", "x" * 32, "mail.x"],
)
def test_upstream_id_rejects_invalid(upstream: str) -> None:
    with pytest.raises(ValueError, match="upstream id"):
        make_tool_name(upstream, "tool")


@pytest.mark.phase(1)
@pytest.mark.parametrize("name", ["nounderscores", "mail_only", "__tool", "mail__"])
def test_split_rejects_names_without_both_parts(name: str) -> None:
    with pytest.raises(ValueError, match="tool name"):
        split_tool_name(name)


@pytest.mark.phase(6)
def test_the_upstream_id_keystone_is_reserved_for_keystones_own_tools() -> None:
    assert is_reserved("keystone")
    for refused in (
        lambda: check_upstream_id("keystone"),
        lambda: make_tool_name("keystone", "await_approval"),
        lambda: split_tool_name("keystone__whoami"),
    ):
        with pytest.raises(ValueError, match="reserved"):
            refused()
    # Only that id: the others that look like it are ordinary.
    for fine in ("keystone2", "keystone_x", "mykeystone", "keys"):
        assert not is_reserved(fine)
        check_upstream_id(fine)
