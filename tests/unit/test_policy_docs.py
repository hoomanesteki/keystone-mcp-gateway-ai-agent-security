"""The policies in docs/policies.md are real: the good ones load and the bad ones are refused."""

import re
from pathlib import Path

import pytest

from keystone.policy.store import PolicyLoadError, load_policies
from keystone.policy.testrunner import load_cases
from tests.fixtures.policies import ROOT, write_policies

DOC = (ROOT / "docs" / "policies.md").read_text()
BLOCK = re.compile(r"```(cedar|cedar-error|cedar-mistake)\n(.*?)```", re.DOTALL)
BLOCKS = BLOCK.findall(DOC)
PATH_LINE = re.compile(r"^// ([a-z/-]+\.cedar)\n")


def path_and_text(text: str) -> tuple[str, str]:
    """A first line `// approval/x.cedar` says where in the policy tree the example belongs."""
    found = PATH_LINE.match(text)
    if found is None:
        return "default/access/example.cedar", text
    return f"default/{found.group(1)}", text[found.end() :]


def load(tmp_path: Path, text: str) -> None:
    path, body = path_and_text(text)
    root = write_policies(tmp_path / "policies", {path: body})
    load_policies(root, ["acme"])


@pytest.mark.phase(4)
def test_the_doc_has_the_five_examples_and_the_mistakes() -> None:
    kinds = [kind for kind, _ in BLOCKS]

    assert kinds.count("cedar") == 5
    assert kinds.count("cedar-error") >= 4
    assert kinds.count("cedar-mistake") >= 1


@pytest.mark.phase(4)
@pytest.mark.parametrize(("kind", "text"), BLOCKS, ids=lambda v: v[:30] if len(v) > 12 else v)
def test_every_example_does_what_the_doc_says(tmp_path: Path, kind: str, text: str) -> None:
    if kind == "cedar-error":
        with pytest.raises(PolicyLoadError):
            load(tmp_path, text)
    else:
        load(tmp_path, text)  # a policy to copy, or one that loads and is wrong, must load


@pytest.mark.phase(4)
def test_the_examples_from_the_pack_are_the_files_in_the_pack() -> None:
    bank = (ROOT / "policies" / "demo" / "approval" / "bank.cedar").read_text()
    mail = (ROOT / "policies" / "acme" / "approval" / "mail.cedar").read_text()
    shown = "".join(text for kind, text in BLOCKS if kind == "cedar")

    def squeezed(source: str) -> str:
        """The policy without its comments, and without any space: the doc wraps the header."""
        return re.sub(r"\s+", "", source[source.index("@id(") :])

    assert squeezed(bank) in squeezed(shown)
    assert squeezed(mail) in squeezed(shown)


@pytest.mark.phase(4)
def test_the_case_example_in_the_doc_is_a_case(tmp_path: Path) -> None:
    [example] = re.findall(r"```yaml\n# a policy case\n(.*?)```", DOC, flags=re.DOTALL)
    path = tmp_path / "example.yaml"
    path.write_text(example)

    [loaded] = load_cases([path])

    assert loaded.case.name == "support cannot transfer"
    assert loaded.case.expect.value == "deny"
