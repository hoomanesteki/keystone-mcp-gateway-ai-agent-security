"""KS-991: a tenant relaxes a default approval rule by listing its id, and only that one."""

from pathlib import Path

import pytest

from keystone.core.types import Effect, Principal, Risk, SessionState, ToolRef, ToolTag
from keystone.policy.engine import CedarPolicyEngine
from keystone.policy.entities import build_context
from keystone.policy.store import PolicyLoadError, PolicyStore, load_policies
from tests.fixtures.calls import make_ctx, make_tool
from tests.fixtures.policies import POLICY_ROOT, copy_pack

OLIVIA = Principal(
    tenant_id="acme",
    user_id="olivia",
    groups=("operators",),
    agent_id="ops-agent",
    agent_trust="high",
)
WRITE = make_tool("files", "write_file", risk=Risk.HIGH, tags=frozenset({ToolTag.EXTERNAL_EFFECT}))
RULE = "untrusted-then-external-effect"


def ask(
    store: PolicyStore, flags: frozenset[ToolTag], tainted: bool = False, tool: ToolRef = WRITE
) -> tuple[Effect, list[str]]:
    session = SessionState(
        session_id="s",
        principal=OLIVIA,
        created_at=make_ctx().received_at,
        flags=set(flags),
        tainted=tainted,
    )
    call = make_ctx(tool=tool, principal=OLIVIA, session=session)
    context = build_context(call, {})
    decision = CedarPolicyEngine(store).evaluate(OLIVIA, "call_tool", tool, context)
    return decision.effect, list(decision.reasons)


@pytest.mark.phase(9)
def test_a_tenant_can_exclude_the_rule_and_keep_the_others() -> None:
    both = frozenset({ToolTag.READS_UNTRUSTED, ToolTag.READS_SENSITIVE})
    kept = PolicyStore(POLICY_ROOT, ["acme", "globex"])
    relaxed = PolicyStore(POLICY_ROOT, ["acme", "globex"], exclusions={"acme": [RULE]})
    kept.start()
    relaxed.start()

    untrusted = frozenset({ToolTag.READS_UNTRUSTED})
    assert ask(kept, untrusted) == (Effect.REQUIRE_APPROVAL, [RULE])
    assert ask(relaxed, untrusted) == (Effect.ALLOW, ["operators-high"])
    # The Rule of Two and the taint rule are still in force for the tenant.
    assert ask(relaxed, both) == (Effect.REQUIRE_APPROVAL, ["rule-of-two"])
    assert ask(relaxed, frozenset(), tainted=True) == (
        Effect.REQUIRE_APPROVAL,
        ["tainted-external-effect"],
    )


@pytest.mark.phase(9)
def test_the_exclusion_is_for_that_tenant_only() -> None:
    store = PolicyStore(POLICY_ROOT, ["acme", "globex"], exclusions={"acme": [RULE]})
    loaded = store.start()

    assert RULE not in {p.id for p in loaded.tenants["acme"].policies}
    assert RULE in {p.id for p in loaded.tenants["globex"].policies}
    assert loaded.tenants["acme"].excluded == frozenset({RULE})
    assert loaded.tenants["globex"].excluded == frozenset()


@pytest.mark.phase(9)
def test_a_tenant_forbid_cannot_remove_the_rule(tmp_path: Path) -> None:
    # The reason the exclusion exists: a forbid in the approval set is refused by the loader.
    root = copy_pack(tmp_path)
    (root / "acme" / "approval" / "relax.cedar").write_text(
        '@id("relax")\nforbid (principal, action, resource);\n'
    )
    with pytest.raises(PolicyLoadError, match="forbid in the approval set"):
        load_policies(root, ["acme"])


@pytest.mark.phase(9)
@pytest.mark.parametrize(
    ("tenant", "ids", "message"),
    [
        ("acme", ["no-such-rule"], 'no-such-rule" is not a policy of the default approval set'),
        ("acme", ["deny-cross-tenant"], "only a rule of the approval set can be excluded"),
        ("nobody", [RULE], "is not a configured tenant"),
    ],
)
def test_an_exclusion_that_names_nothing_is_refused(
    tenant: str, ids: list[str], message: str
) -> None:
    with pytest.raises(PolicyLoadError, match=message):
        load_policies(POLICY_ROOT, ["acme"], exclusions={tenant: ids})
