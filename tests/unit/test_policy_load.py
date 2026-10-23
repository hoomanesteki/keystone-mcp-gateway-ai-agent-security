"""KS-403: the loader reads the policy files, checks them and names every problem."""

from pathlib import Path

import pytest

from keystone.core.canonical import canonical_json, sha256_hex
from keystone.policy.store import PolicyLoadError, PolicySet, load_policies
from tests.fixtures.policies import (
    POLICY_ROOT,
    SCHEMA_TEXT,
    forbid,
    permit,
    write_policies,
)

TENANTS = ("acme", "globex")


def load(root: Path, tenants: tuple[str, ...] = TENANTS, demo: bool = False) -> PolicySet:
    return load_policies(root, tenants, include_demo=demo)


def problems(root: Path, tenants: tuple[str, ...] = TENANTS, demo: bool = False) -> tuple[str, ...]:
    with pytest.raises(PolicyLoadError) as raised:
        load(root, tenants, demo)
    return raised.value.problems


def tree(tmp_path: Path, **files: str) -> Path:
    """A tree with a default set and the given files. `a__b__c` stands for a/b/c.cedar."""
    named = {key.replace("__", "/") + ".cedar": text for key, text in files.items()}
    named.setdefault("default/access/base.cedar", permit("base-permit"))
    return write_policies(tmp_path / "policies", named)


@pytest.mark.phase(4)
def test_the_shipped_default_pack_loads() -> None:
    loaded = load(POLICY_ROOT, ("acme", "globex"))

    ids = {policy.id for policy in loaded.policies}
    assert {
        "same-tenant-low-medium",
        "operators-high",
        "admins-critical",
        "deny-cross-tenant",
    } <= ids
    assert set(loaded.tenants) == {"acme", "globex"}
    paths = [f.path for f in loaded.files]
    assert paths == sorted(paths)
    assert "default/access/base.cedar" in paths and "schema.cedarschema" in paths


@pytest.mark.phase(4)
def test_a_tenants_sets_are_default_plus_its_own(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        acme__access__team=permit("acme-only"),
        acme__approval__mail=permit("acme-asks"),
        globex__access__team=forbid("globex-only"),
    )

    loaded = load(root)

    acme = {(p.id, p.kind) for p in loaded.tenants["acme"].policies}
    globex = {(p.id, p.kind) for p in loaded.tenants["globex"].policies}
    assert acme == {("base-permit", "access"), ("acme-only", "access"), ("acme-asks", "approval")}
    assert globex == {("base-permit", "access"), ("globex-only", "access")}
    assert len(loaded.tenants["acme"].access) == 2 and len(loaded.tenants["acme"].approval) == 1
    assert len(loaded.tenants["globex"].approval) == 0


@pytest.mark.phase(4)
def test_the_demo_policies_apply_only_when_asked_for(tmp_path: Path) -> None:
    root = tree(tmp_path, demo__approval__bank=permit("demo-asks"))

    without = load(root, demo=False)
    with_demo = load(root, demo=True)

    assert "demo-asks" not in {p.id for p in without.policies}
    assert "demo-asks" in {p.id for p in with_demo.policies}
    for tenant in ("acme", "globex"):
        assert "demo-asks" in {p.id for p in with_demo.tenants[tenant].policies}
    assert without.version != with_demo.version


@pytest.mark.phase(4)
def test_the_version_is_the_sha256_of_the_sorted_paths_and_contents(tmp_path: Path) -> None:
    root = tree(tmp_path, acme__access__team=permit("acme-only"))

    loaded = load(root)

    expected = sorted(
        [
            ["acme/access/team.cedar", permit("acme-only")],
            ["default/access/base.cedar", permit("base-permit")],
            ["schema.cedarschema", SCHEMA_TEXT],
        ]
    )
    assert loaded.version == sha256_hex(canonical_json(expected))
    assert load(root).version == loaded.version


@pytest.mark.phase(4)
def test_the_version_does_not_depend_on_the_order_files_were_written(tmp_path: Path) -> None:
    first = write_policies(
        tmp_path / "one",
        {
            "default/access/a.cedar": permit("a-permit"),
            "default/access/b.cedar": permit("b-permit"),
            "acme/access/c.cedar": permit("c-permit"),
        },
    )
    second = write_policies(
        tmp_path / "two",
        {
            "acme/access/c.cedar": permit("c-permit"),
            "default/access/b.cedar": permit("b-permit"),
            "default/access/a.cedar": permit("a-permit"),
        },
    )

    assert load(first).version == load(second).version


@pytest.mark.phase(4)
@pytest.mark.parametrize("change", ["content", "name", "schema"])
def test_the_version_changes_when_anything_that_is_read_changes(
    tmp_path: Path, change: str
) -> None:
    root = tree(tmp_path)
    before = load(root).version
    base = root / "default" / "access" / "base.cedar"

    if change == "content":
        base.write_text(permit("base-permit", "context.hour_utc < 20"))
    elif change == "name":
        base.rename(root / "default" / "access" / "renamed.cedar")
    else:
        (root / "schema.cedarschema").write_text(SCHEMA_TEXT + "\n// a comment\n")

    assert load(root).version != before


@pytest.mark.phase(4)
def test_the_files_keep_their_content_and_hash(tmp_path: Path) -> None:
    loaded = load(tree(tmp_path))

    base = next(f for f in loaded.files if f.path == "default/access/base.cedar")
    assert base.content == permit("base-permit")
    assert len(base.sha256) == 64


@pytest.mark.phase(4)
def test_a_policy_without_an_id_is_named_by_file_and_place(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        default__access__second=permit("fine") + "permit (principal, action, resource);\n",
    )

    [problem] = problems(root)

    assert problem.startswith("default/access/second.cedar: policy 2 (a permit) has no @id")
    assert "audit log" in problem


@pytest.mark.phase(4)
@pytest.mark.parametrize(
    ("identifier", "fragment"),
    [
        ("Not_Kebab", "not kebab case"),
        ("trailing-", "not kebab case"),
        ("double--dash", "not kebab case"),
        ("1starts-with-digit", "not kebab case"),
        ("", "not kebab case"),
        ("default-deny", "uses as a reason"),
        ("policy-error", "uses as a reason"),
    ],
)
def test_ids_must_be_kebab_case_and_not_the_engines_own(
    tmp_path: Path, identifier: str, fragment: str
) -> None:
    root = tree(
        tmp_path,
        default__access__odd=f'@id("{identifier}")\npermit (principal, action, resource);\n',
    )

    [problem] = problems(root)

    assert fragment in problem and problem.startswith("default/access/odd.cedar")


@pytest.mark.phase(4)
def test_a_duplicate_id_in_one_tenants_combined_set_is_refused(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        acme__access__team=permit("base-permit"),
        acme__approval__mail=permit("base-permit"),
    )

    [problem] = problems(root)

    assert 'policy id "base-permit" is used more than once' in problem
    assert "default/access/base.cedar" in problem and "acme/approval/mail.cedar" in problem


@pytest.mark.phase(4)
def test_the_same_id_in_two_tenants_is_fine(tmp_path: Path) -> None:
    root = tree(
        tmp_path, acme__access__team=permit("team-rule"), globex__access__team=permit("team-rule")
    )

    assert load(root).tenants.keys() == {"acme", "globex"}


@pytest.mark.phase(4)
def test_a_duplicate_between_two_shared_files_is_reported_once(tmp_path: Path) -> None:
    root = tree(tmp_path, default__access__again=permit("base-permit"))

    found = problems(root)

    assert len(found) == 1


@pytest.mark.phase(4)
def test_a_forbid_in_the_approval_set_is_refused_with_a_reason(tmp_path: Path) -> None:
    root = tree(tmp_path, acme__approval__mail=forbid("block-mail"))

    [problem] = problems(root)

    assert problem.startswith('acme/approval/mail.cedar: "block-mail" is a forbid')
    assert "approval set may hold permit policies only" in problem
    assert "access/" in problem


@pytest.mark.phase(4)
def test_a_syntax_error_names_its_file_and_the_other_files_still_load(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        default__access__broken="permit (principal, action, resource",
        acme__access__also_broken="forbid (",
    )

    found = problems(root)

    assert len(found) == 2
    assert sorted(p.split(":")[0] for p in found) == [
        "acme/access/also_broken.cedar",
        "default/access/broken.cedar",
    ]


@pytest.mark.phase(4)
def test_a_validation_error_names_the_file_the_policy_and_the_mistake(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        acme__access__typo=permit("typo-rule", "resource.rsik_level <= 2"),
        acme__approval__unsafe=permit("unsafe-rule", "context.args.amount > 5"),
        acme__access__wrong_type=permit("wrong-type", "context.agent_trust > 1"),
    )

    found = problems(root)

    text = "\n".join(found)
    assert 'acme/access/typo.cedar: policy "typo-rule": attribute `rsik_level`' in text
    assert 'acme/approval/unsafe.cedar: policy "unsafe-rule": unable to guarantee safety' in text
    assert 'acme/access/wrong_type.cedar: policy "wrong-type": unexpected type' in text
    assert "for policy `policy" not in text  # Cedar's own numbering is never shown


@pytest.mark.phase(4)
def test_every_problem_is_reported_not_only_the_first(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        default__access__one="permit (principal, action, resource);\n",
        acme__access__two=permit("Bad_Id"),
        acme__approval__three=forbid("a-forbid"),
        globex__access__four="permit (",
    )

    assert len(problems(root)) == 4


@pytest.mark.phase(4)
def test_a_policy_template_is_refused(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        acme__access__template=(
            '@id("templated") permit (principal == ?principal, action, resource);\n'
        ),
    )

    [problem] = problems(root)

    assert problem.startswith("acme/access/template.cedar: ") and "templates" in problem


@pytest.mark.phase(4)
def test_a_directory_or_file_cedar_would_not_read_is_an_error(tmp_path: Path) -> None:
    root = tree(tmp_path)
    (root / "acem" / "access").mkdir(parents=True)
    (root / "acem" / "access" / "x.cedar").write_text(forbid("misspelled-tenant"))
    (root / "acme" / "aproval").mkdir(parents=True)
    (root / "acme" / "aproval" / "x.cedar").write_text(permit("misspelled-dir"))
    (root / "acme" / "access").mkdir(parents=True)
    (root / "acme" / "access" / "base.cdar").write_text(forbid("misspelled-suffix"))
    (root / "acme" / "access" / "nested").mkdir()
    (root / "acme" / "access" / "nested" / "y.cedar").write_text(forbid("nested"))
    (root / "acme" / "loose.cedar").write_text(forbid("loose"))
    (root / "acme" / "access" / ".hidden.swp").write_text("junk")

    found = "\n".join(problems(root))

    assert "acem/: not a policy directory" in found
    assert "acme/aproval/: use access/ or approval/ inside acme/" in found
    assert "acme/access/base.cdar: not read, policy files end in .cedar" in found
    assert "acme/access/nested/: policies are read from acme/access/ only" in found
    assert "acme/loose.cedar: not read, put it in acme/access/ or acme/approval/" in found
    assert ".hidden.swp" not in found


@pytest.mark.phase(4)
def test_a_missing_root_schema_or_default_directory_is_an_error(tmp_path: Path) -> None:
    assert problems(tmp_path / "nowhere") == (
        f"the policy directory {tmp_path / 'nowhere'} does not exist",
    )

    no_schema = write_policies(tmp_path / "a", {"default/access/b.cedar": permit("b")}, schema=None)
    assert any(p.startswith("schema.cedarschema: cannot be read") for p in problems(no_schema))

    no_default = write_policies(tmp_path / "b")
    assert any(p.startswith("default/: missing") for p in problems(no_default))

    broken_schema = write_policies(
        tmp_path / "c",
        {"default/access/b.cedar": permit("b")},
        schema="namespace Keystone { entity }",
    )
    assert any(p.startswith("schema.cedarschema: ") for p in problems(broken_schema))


@pytest.mark.phase(4)
def test_a_tenant_may_not_be_called_default_or_demo(tmp_path: Path) -> None:
    found = problems(tree(tmp_path), tenants=("acme", "demo"))

    assert any("tenant id 'demo' is the name of a shared policy directory" in p for p in found)


@pytest.mark.phase(4)
def test_an_empty_default_set_loads_and_holds_no_policy(tmp_path: Path) -> None:
    root = write_policies(tmp_path / "empty", {"default/access/.keep": ""})
    (root / "default" / "access" / ".keep").unlink()

    loaded = load(root)

    assert loaded.policies == ()
    assert len(loaded.tenants["acme"].access) == 0


@pytest.mark.phase(4)
def test_with_no_tenants_the_shared_files_are_still_checked(tmp_path: Path) -> None:
    root = tree(tmp_path, default__approval__bad=forbid("shared-forbid"))

    found = problems(root, tenants=())

    assert len(found) == 1 and "forbid in the approval set" in found[0]


@pytest.mark.phase(4)
def test_a_file_that_is_not_utf8_is_an_error_not_a_crash(tmp_path: Path) -> None:
    root = tree(tmp_path)
    (root / "default" / "access" / "bad.cedar").write_bytes(b"\xff\xfe permit")

    [problem] = problems(root)

    assert problem == "default/access/bad.cedar: cannot be read (not valid UTF-8)"
