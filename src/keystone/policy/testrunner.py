"""Policy cases as data (KS-408): decisions the policies must keep making, checked like code.

A case names a caller, a tool, a call and the decision the policies must give:

    - name: support cannot transfer
      tenant: acme
      principal: {user: alice, groups: [support], agent: support-agent, trust: standard}
      tool: {name: bank__transfer, risk: high, tags: [external_effect]}
      args: {amount: 90000}
      session: {flags: [], tainted: false}
      expect: deny
      expect_reasons: [default-deny]          # optional

`args` are the facts a policy reads (`context.args`), as the extractors would give them. A case
can give the call's own `arguments` instead, with the tool's `extract` config, to test the
extractors and the policies together. The caller's tenant, the tool's tenant (the same unless
`tool.tenant` says otherwise), the action (`call_tool` unless `action` says `list_tool`), the hour
and the call count can be set.

The cases run through the same engine and the same loader as the gateway, so a case that passes
here is the decision Keystone makes. With `--coverage`, a policy that no case exercised is listed
and fails the run: a rule nobody tests is a rule a pull request can change without anyone noticing.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from structlog.testing import capture_logs

from keystone.core.types import Effect, Principal, Risk, SessionState, ToolRef, ToolTag
from keystone.policy.engine import CedarPolicyEngine, Trace
from keystone.policy.entities import Action, build_context
from keystone.policy.extractors import extract
from keystone.policy.store import (
    DEFAULT_DIR,
    DEMO_DIR,
    Kind,
    PolicyLoadError,
    PolicySet,
    PolicyStore,
)

CASE_SUFFIXES = (".yaml", ".yml")
NAME_WIDTH = 46


class _Model(BaseModel):
    # A misspelled key must fail, not quietly leave a case weaker than it looks.
    model_config = ConfigDict(extra="forbid")


class PrincipalSpec(_Model):
    user: str
    groups: list[str] = Field(default_factory=list)
    agent: str = "test-agent"
    trust: Literal["low", "standard", "high"] = "standard"
    roles: list[str] = Field(default_factory=list)


class ToolSpec(_Model):
    name: str = Field(pattern=r"^[a-zA-Z0-9]+(_[a-zA-Z0-9]+)*__[a-zA-Z0-9_-]+$")
    risk: Risk = Risk.MEDIUM
    tags: list[ToolTag] = Field(default_factory=list)
    tenant: str | None = None
    extract: dict[str, str] = Field(default_factory=dict)


class SessionSpec(_Model):
    flags: list[ToolTag] = Field(default_factory=list)
    tainted: bool = False
    call_count: int = Field(default=0, ge=0)


class Case(_Model):
    name: str = Field(min_length=1)
    tenant: str
    principal: PrincipalSpec
    tool: ToolSpec
    args: dict[str, int | str | bool] | None = None
    arguments: dict[str, Any] | None = None
    session: SessionSpec = Field(default_factory=SessionSpec)
    action: Action = "call_tool"
    hour: int = Field(default=12, ge=0, le=23)
    expect: Effect
    expect_reasons: list[str] | None = None


class CaseError(Exception):
    """The case files cannot be read as cases. `problems` names each one."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = tuple(problems)
        super().__init__("; ".join(self.problems))


@dataclass(frozen=True)
class LoadedCase:
    case: Case
    source: str  # the file it came from


@dataclass(frozen=True)
class Outcome:
    case: LoadedCase
    trace: Trace
    problems: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.problems


@dataclass(frozen=True)
class Unmatched:
    id: str
    file: str


@dataclass(frozen=True)
class Report:
    outcomes: tuple[Outcome, ...]
    unmatched: tuple[Unmatched, ...] = field(default=())
    coverage: bool = False
    # Warnings and errors the engine logged while deciding, such as why a case ended in
    # policy-error. Debug and info lines are left out.
    notes: tuple[str, ...] = field(default=())

    @property
    def failed(self) -> list[Outcome]:
        return [o for o in self.outcomes if not o.passed]

    @property
    def ok(self) -> bool:
        return not self.failed and not (self.coverage and self.unmatched)


def case_files(paths: Sequence[Path]) -> list[Path]:
    """The YAML files named, or found in the named directories, in a stable order."""
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found += sorted(p for p in path.rglob("*") if p.suffix in CASE_SUFFIXES and p.is_file())
        elif path.is_file():
            found.append(path)
        else:
            raise CaseError([f"{path}: no such file or directory"])
    return found


def load_cases(paths: Sequence[Path]) -> list[LoadedCase]:
    """Read and check every case. Raises CaseError, naming every problem, if any is wrong."""
    problems: list[str] = []
    loaded: list[LoadedCase] = []
    for path in case_files(paths):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            problems.append(f"{path}: cannot be read as YAML ({type(exc).__name__})")
            continue
        if not isinstance(document, list):
            problems.append(f"{path}: a case file is a list of cases")
            continue
        names: set[str] = set()
        for index, item in enumerate(document, start=1):
            label = item.get("name") if isinstance(item, dict) else None
            where = f"{path}: case {index}" + (f" ({label!r})" if label else "")
            try:
                case = Case.model_validate(item)
            except ValidationError as exc:
                for error in exc.errors():
                    place = ".".join(str(part) for part in error["loc"])
                    problems.append(f"{where}: {place}: {error['msg']}")
                continue
            if case.name in names:
                problems.append(f"{where}: another case in this file has the same name")
            names.add(case.name)
            if case.args is not None and case.arguments is not None:
                problems.append(f"{where}: give args or arguments, not both")
                continue
            loaded.append(LoadedCase(case, str(path)))
    if problems:
        raise CaseError(problems)
    return loaded


def tenants_of(root: Path, cases: Sequence[LoadedCase]) -> list[str]:
    """The tenants to load policies for: those the cases name and the directories under the root
    that are neither default nor demo."""
    named = {c.case.tenant for c in cases} | {
        c.case.tool.tenant for c in cases if c.case.tool.tenant
    }
    on_disk = (
        {p.name for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")}
        if root.is_dir()
        else set()
    )
    return sorted((named | on_disk) - {DEFAULT_DIR, DEMO_DIR})


def _build(case: Case) -> tuple[Principal, ToolRef, dict[str, Any]]:
    principal = Principal(
        tenant_id=case.tenant,
        user_id=case.principal.user,
        groups=tuple(case.principal.groups),
        agent_id=case.principal.agent,
        agent_trust=case.principal.trust,
        roles=tuple(case.principal.roles),
    )
    upstream, _, name = case.tool.name.partition("__")
    tool = ToolRef(
        name=case.tool.name,
        upstream_id=upstream,
        upstream_tool_name=name,
        tenant_id=case.tool.tenant or case.tenant,
        description="",
        input_schema={},
        risk=case.tool.risk,
        tags=frozenset(case.tool.tags),
        extractors=dict(case.tool.extract),
        description_hash="",
        schema_hash="",
    )
    session = SessionState(
        session_id="case",
        principal=principal,
        flags=set(case.session.flags),
        tainted=case.session.tainted,
        call_count=case.session.call_count,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    facts = extract(case.arguments or {}, tool.extractors) if case.arguments is not None else None
    context = build_context(
        session,
        facts if facts is not None else (case.args or {}),
        now=datetime(2026, 1, 1, case.hour, tzinfo=UTC),
    )
    return principal, tool, context


def run_case(engine: CedarPolicyEngine, loaded: LoadedCase) -> Outcome:
    case = loaded.case
    principal, tool, context = _build(case)
    trace = engine.trace(principal, case.action, tool, context)
    decision = trace.decision
    problems = []
    if decision.effect is not case.expect:
        problems.append(f"expected {case.expect.value}, got {decision.effect.value}")
    if case.expect_reasons is not None and sorted(case.expect_reasons) != sorted(decision.reasons):
        problems.append(
            f"expected reasons {sorted(case.expect_reasons)}, got {sorted(decision.reasons)}"
        )
    return Outcome(loaded, trace, tuple(problems))


def _unmatched(policy_set: PolicySet, outcomes: Sequence[Outcome]) -> tuple[Unmatched, ...]:
    """Policies that were not among the reasons of any pass of any case. A policy is identified by
    its file and id, because two tenants may each have a policy of the same id."""
    matched: set[tuple[str, str]] = set()
    for outcome in outcomes:
        tenant = policy_set.tenants.get(outcome.case.case.tenant)
        if tenant is None:
            continue
        files = {(p.id, p.kind): p.file for p in tenant.policies}
        passes: list[tuple[Kind, tuple[str, ...]]] = [
            ("access", outcome.trace.access),
            ("approval", outcome.trace.approval),
        ]
        for kind, ids in passes:
            matched |= {(files[(i, kind)], i) for i in ids if (i, kind) in files}
    return tuple(
        Unmatched(p.id, p.file)
        for p in sorted(policy_set.policies, key=lambda p: (p.file, p.id))
        if (p.file, p.id) not in matched
    )


def run(root: Path, case_paths: Sequence[Path], *, coverage: bool = False) -> Report:
    """Load the policies under `root` and the cases, and decide every case. Raises PolicyLoadError
    when the policies do not load and CaseError when the cases cannot be read."""
    cases = load_cases(case_paths)
    store = PolicyStore(root, tenants_of(root, cases), include_demo=True)
    store.start()
    engine = CedarPolicyEngine(store)
    with capture_logs() as logs:
        outcomes = tuple(run_case(engine, loaded) for loaded in cases)
    notes = tuple(
        f"{entry['log_level']}: {entry['event']} "
        + " ".join(f"{k}={v}" for k, v in sorted(entry.items()) if k not in {"event", "log_level"})
        for entry in logs
        if entry["log_level"] in ("warning", "error")
    )
    unmatched = _unmatched(store.current, outcomes) if coverage else ()
    return Report(outcomes, unmatched, coverage, notes)


def render(report: Report) -> str:
    """A table of the cases, the problems of the ones that failed, and the totals."""
    rows = [("RESULT", "CASE", "EXPECTED", "GOT", "REASONS")]
    for outcome in report.outcomes:
        decision = outcome.trace.decision
        name = outcome.case.case.name
        shown = name if len(name) <= NAME_WIDTH else name[: NAME_WIDTH - 3] + "..."
        rows.append(
            (
                "pass" if outcome.passed else "FAIL",
                shown,
                outcome.case.case.expect.value,
                decision.effect.value,
                ",".join(sorted(decision.reasons)),
            )
        )
    widths = [max(len(row[i]) for row in rows) for i in range(5)]
    lines = [
        "  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)).rstrip()
        for row in rows
    ]
    for outcome in report.failed:
        lines.append("")
        lines.append(f"FAIL {outcome.case.case.name!r} ({outcome.case.source})")
        lines += [f"  {problem}" for problem in outcome.problems]
    if report.notes:
        lines += ["", "the engine logged:", *(f"  {note}" for note in report.notes)]
    total = len(report.outcomes)
    lines += [
        "",
        f"{total} cases, {total - len(report.failed)} passed, {len(report.failed)} failed",
    ]
    if report.coverage:
        if report.unmatched:
            lines.append(f"coverage: {len(report.unmatched)} policies no case matched:")
            lines += [f"  {u.file}: {u.id}" for u in report.unmatched]
        else:
            lines.append("coverage: every policy was matched by at least one case")
    return "\n".join(lines)


__all__ = [
    "Case",
    "CaseError",
    "LoadedCase",
    "Outcome",
    "PolicyLoadError",
    "Report",
    "Unmatched",
    "load_cases",
    "render",
    "run",
    "run_case",
]
