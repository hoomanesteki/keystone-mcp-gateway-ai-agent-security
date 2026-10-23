#!/usr/bin/env python3
"""Measure how long the policy engine takes to decide one call.

    uv run python scripts/bench_policy.py [--runs 10000]

It times CedarPolicyEngine.evaluate: the entities are built for each call, then the access set is
asked, then the approval set when access allowed. The shipped policy pack is measured as it is,
and so is a tenant with 50 policies (the shapes a team writes: per-group permits, per-tool forbids
on the hour, per-tool approvals on an amount). The last row adds what the policy slot does around
the engine: it extracts the arguments and builds the context. The numbers in
docs/spikes/cedarpy.md come from here. Run it on a quiet machine: another process doubles the
figures.
"""

from __future__ import annotations

import argparse
import platform
import shutil
import statistics
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from keystone.core.types import Decision, Principal, Risk, SessionState, ToolRef, ToolTag
from keystone.policy.engine import CedarPolicyEngine
from keystone.policy.entities import build_context
from keystone.policy.extractors import extract
from keystone.policy.store import PolicyStore

ROOT = Path(__file__).resolve().parents[1]
POLICY_ROOT = ROOT / "policies"
WARMUP = 200


def _policy(kind: str, name: str, scope: str, condition: str) -> str:
    return f'@id("{name}")\n{kind} ({scope}) when {{ {condition} }};\n'


def fifty_policies() -> dict[str, str]:
    """The plan's access pack plus 14 + 16 + 16 policies of the shapes a tenant writes: 50 in all,
    in `acme`'s combined set. Keys are paths under the policy root."""
    groups = "".join(
        _policy(
            "permit",
            f"allow-group-{i}",
            f'principal in Keystone::Group::"group{i}", action, resource',
            'resource.tenant == principal.tenant && context.agent_trust != "low"',
        )
        for i in range(14)
    )
    forbids = "".join(
        _policy(
            "forbid",
            f"no-tool-{i}-at-night",
            f'principal, action == Keystone::Action::"call_tool", '
            f'resource == Keystone::Tool::"tool{i}__go"',
            "context.hour_utc < 6",
        )
        for i in range(16)
    )
    approvals = "".join(
        _policy(
            "permit",
            f"approve-tool-{i}-large",
            f'principal, action == Keystone::Action::"call_tool", '
            f'resource == Keystone::Tool::"tool{i}__go"',
            f"context.args has amount && context.args.amount > {100 + i}",
        )
        for i in range(15)
    ) + _policy(
        "permit",
        "approve-transfer-over-500",
        'principal, action == Keystone::Action::"call_tool", '
        'resource == Keystone::Tool::"bank__transfer"',
        "context.args has amount && context.args.amount > 500",
    )
    return {
        "default/access/base.cedar": (POLICY_ROOT / "default/access/base.cedar").read_text(),
        "default/access/groups.cedar": groups,
        "acme/access/night.cedar": forbids,
        "acme/approval/large.cedar": approvals,
    }


def write_tree(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(POLICY_ROOT / "schema.cedarschema", root / "schema.cedarschema")
    for relative, text in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return root


def measure(
    engine: CedarPolicyEngine, runs: int, principal: Principal, tool: ToolRef, amount: int
) -> tuple[list[float], Decision]:
    session = SessionState(session_id="bench", principal=principal, created_at=datetime.now(UTC))
    context = build_context(session, {"amount": amount})
    for _ in range(WARMUP):
        engine.evaluate(principal, "call_tool", tool, context)
    samples = []
    decision = engine.evaluate(principal, "call_tool", tool, context)
    for _ in range(runs):
        started = time.perf_counter()
        decision = engine.evaluate(principal, "call_tool", tool, context)
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()
    return samples, decision


def measure_slot(
    engine: CedarPolicyEngine,
    runs: int,
    principal: Principal,
    tool: ToolRef,
    arguments: dict[str, object],
) -> tuple[list[float], Decision]:
    """The same call as the policy slot makes it: extract, build the context, decide."""
    session = SessionState(session_id="bench", principal=principal, created_at=datetime.now(UTC))

    def once() -> Decision:
        context = build_context(session, extract(arguments, tool.extractors), now=datetime.now(UTC))
        return engine.evaluate(principal, "call_tool", tool, context)

    for _ in range(WARMUP):
        once()
    samples = []
    decision = once()
    for _ in range(runs):
        started = time.perf_counter()
        decision = once()
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()
    return samples, decision


def percentile(samples: list[float], p: float) -> float:
    """`samples` is sorted."""
    return samples[int(p / 100 * (len(samples) - 1))]


def row(label: str, count: int, decision: Decision, samples: list[float]) -> str:
    return (
        f"{label:32} {count:>8} {decision.effect.value:18} "
        f"{statistics.median(samples):>8.3f} {percentile(samples, 95):>8.3f} "
        f"{percentile(samples, 99):>8.3f}"
    )


def tool_of(upstream: str, name: str, risk: Risk, tags: frozenset[ToolTag]) -> ToolRef:
    return ToolRef(
        name=f"{upstream}__{name}",
        upstream_id=upstream,
        upstream_tool_name=name,
        tenant_id="acme",
        description="",
        input_schema={},
        risk=risk,
        tags=tags,
        description_hash="d",
        schema_hash="s",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--runs", type=int, default=10_000)
    args = parser.parse_args(argv)

    operator = Principal(
        tenant_id="acme",
        user_id="olivia",
        groups=("operators",),
        agent_id="ops-agent",
        agent_trust="high",
    )
    transfer = tool_of("bank", "transfer", Risk.HIGH, frozenset({ToolTag.EXTERNAL_EFFECT}))
    cases = [
        ("shipped pack", None, transfer, 100),
        ("50 policies, allowed", fifty_policies(), transfer, 50),
        ("50 policies, needs approval", fifty_policies(), transfer, 900),
    ]
    priced = tool_of("bank", "transfer", Risk.HIGH, frozenset({ToolTag.EXTERNAL_EFFECT}))
    priced = priced.model_copy(update={"extractors": {"amount": "$.amount | cents"}})
    print(f"{platform.platform()}, Python {platform.python_version()}, {args.runs} runs each")
    print(f"{'set':32} {'policies':>8} {'decision':18} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8}")
    with tempfile.TemporaryDirectory() as scratch:
        for label, files, tool, amount in cases:
            root = write_tree(Path(scratch) / label.replace(" ", "-"), files) if files else None
            store = PolicyStore(root or POLICY_ROOT, ["acme"], include_demo=True)
            store.start()
            engine = CedarPolicyEngine(store)
            samples, decision = measure(engine, args.runs, operator, tool, amount)
            count = len(store.current.tenants["acme"].policies)
            print(row(label, count, decision, samples))
        store = PolicyStore(POLICY_ROOT, ["acme"], include_demo=True)
        store.start()
        samples, decision = measure_slot(
            CedarPolicyEngine(store), args.runs, operator, priced, {"amount": 900.5}
        )
        count = len(store.current.tenants["acme"].policies)
        print(row("shipped pack, whole slot", count, decision, samples))
    return 0


if __name__ == "__main__":
    sys.exit(main())
