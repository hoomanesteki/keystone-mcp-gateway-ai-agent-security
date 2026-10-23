"""Policies loaded from files, checked, versioned and reloaded safely (KS-403).

Layout under the policy root:

    schema.cedarschema          the one Cedar schema (plan section 3.8)
    default/access/*.cedar      permits and forbids that apply to every tenant
    default/approval/*.cedar    permits that ask for approval, for every tenant
    <tenant>/access/*.cedar     the same, for one tenant
    <tenant>/approval/*.cedar
    demo/access/*.cedar         read only when `policy.include_demo` is on
    demo/approval/*.cedar

A tenant's access set is default + demo (if on) + its own; so is its approval set. The access set
is standard Cedar: deny unless a permit matches and no forbid does. The approval set holds permits
only; it is asked after access allowed, and a permit that matches means a person must approve.

A set that has any problem is refused whole, with every problem named, so a bad edit never leaves a
tenant with half its rules. The loader is stricter than Cedar on purpose. A directory or file that
Cedar would never read (a misspelled `aproval/`, a `base.cdar`) is an error, because a rule that
silently does not load is a rule someone believes is in force.
"""

from __future__ import annotations

import hashlib
import re
import signal
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

import anyio
import structlog

from keystone.core.canonical import canonical_json, sha256_hex
from keystone.policy.cedar import (
    CedarError,
    CedarSchema,
    CompiledPolicies,
    PolicyMeta,
    read_policies,
    validate_policies,
)

log = structlog.get_logger()

SCHEMA_FILE = "schema.cedarschema"
DEFAULT_DIR = "default"
DEMO_DIR = "demo"
SHARED_DIRS = (DEFAULT_DIR, DEMO_DIR)
KINDS = ("access", "approval")
SUFFIX = ".cedar"
# Names the engine and the pipeline use as reasons. A policy with one of them would be confused
# with the engine's own answer in the audit log.
RESERVED_IDS = frozenset({"default-deny", "policy-error", "no-decision"})
ID_FORM = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")
# Cedar names the policy in a validation message ("for policy `policy3`, ..."). The loader says
# which file and which id instead.
POSITIONAL_PREFIX = re.compile(r"^for policy `policy\d+`, ")

Kind = Literal["access", "approval"]


class PolicyLoadError(Exception):
    """The files do not make a usable policy set. `problems` names every one, each starting with
    the file it is about."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = tuple(problems)
        super().__init__("; ".join(self.problems))


class PolicyNotLoaded(RuntimeError):
    """The store has no policy set in force yet."""


@dataclass(frozen=True)
class PolicyFile:
    """A file that is part of the set: the schema or one `.cedar` file."""

    path: str  # relative to the policy root, with forward slashes
    content: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()


@dataclass(frozen=True)
class PolicyInfo:
    id: str
    effect: Literal["permit", "forbid"]
    kind: Kind
    file: str


@dataclass(frozen=True)
class TenantPolicies:
    """What applies to one tenant: its access set and its approval set, each parsed once."""

    tenant_id: str
    access: CompiledPolicies
    approval: CompiledPolicies
    policies: tuple[PolicyInfo, ...]


@dataclass(frozen=True)
class PolicySet:
    """Everything loaded from one policy root. Immutable: a reload makes a new one."""

    version: str
    schema: CedarSchema
    tenants: Mapping[str, TenantPolicies]
    files: tuple[PolicyFile, ...]
    policies: tuple[PolicyInfo, ...]  # every policy of every file read, once


@dataclass(frozen=True)
class _Source:
    path: str
    group: str  # default, demo, or a tenant id
    kind: Kind
    text: str
    metas: tuple[PolicyMeta, ...]


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _directories(path: Path) -> list[Path]:
    return sorted(
        (p for p in path.iterdir() if p.is_dir() and not p.name.startswith(".")),
        key=lambda p: p.name,
    )


def _scan_group(root: Path, group: str, problems: list[str]) -> dict[Kind, list[Path]]:
    """The `.cedar` files of one group, by kind. Anything Cedar would not read is a problem."""
    found: dict[Kind, list[Path]] = {"access": [], "approval": []}
    directory = root / group
    if not directory.is_dir():
        return found
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        if entry.name.startswith("."):
            continue
        relative = _relative(entry, root)
        if entry.is_dir() and entry.name in KINDS:
            kind: Kind = "access" if entry.name == "access" else "approval"
            for item in sorted(entry.iterdir(), key=lambda p: p.name):
                if item.name.startswith("."):
                    continue
                item_path = _relative(item, root)
                if item.is_dir():
                    problems.append(f"{item_path}/: policies are read from {relative}/ only")
                elif not item.name.endswith(SUFFIX):
                    problems.append(f"{item_path}: not read, policy files end in {SUFFIX}")
                else:
                    found[kind].append(item)
        elif entry.is_dir():
            problems.append(f"{relative}/: use access/ or approval/ inside {group}/")
        elif entry.name.endswith(SUFFIX):
            problems.append(f"{relative}: not read, put it in {group}/access/ or {group}/approval/")
    return found


def _read(root: Path, path: Path, problems: list[str]) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else "not valid UTF-8"
        problems.append(f"{_relative(path, root)}: cannot be read ({reason})")
        return None


def _ordinal(position: int) -> str:
    return f"policy {position + 1}"


def _check_source(source: _Source, problems: list[str]) -> None:
    for meta in source.metas:
        where = f"{source.path}: {_ordinal(meta.position)} (a {meta.effect})"
        if meta.id is None:
            problems.append(
                f'{where} has no @id; add @id("some-kebab-case-name") above it, because the '
                "audit log names the policies that decide a call"
            )
            continue
        if not ID_FORM.fullmatch(meta.id):
            problems.append(
                f'{where} has the id "{meta.id}", which is not kebab case (lowercase letters, '
                "digits and single dashes, starting with a letter)"
            )
        elif meta.id in RESERVED_IDS:
            problems.append(f'{where} has the id "{meta.id}", which the engine uses as a reason')
        if source.kind == "approval" and meta.effect == "forbid":
            problems.append(
                f'{source.path}: "{meta.id}" is a forbid in the approval set. The approval set '
                "may hold permit policies only: a policy there can ask for approval but never "
                "block a call. Put a forbid in access/ instead"
            )


@dataclass(frozen=True)
class _Origin:
    source: _Source
    meta: PolicyMeta


def _compose(sources: Sequence[_Source]) -> tuple[str, list[_Origin]]:
    """One policy text from several files, and where each of its policies came from. Cedar
    numbers the policies of the text in order, which is the order of these origins."""
    origins = [_Origin(source, meta) for source in sources for meta in source.metas]
    return "\n\n".join(source.text for source in sources), origins


def _validate(
    kind: Kind, sources: Sequence[_Source], schema: CedarSchema, problems: list[str]
) -> CompiledPolicies | None:
    text, origins = _compose(sources)
    for found in validate_policies(text, schema):
        message = POSITIONAL_PREFIX.sub("", found.message)
        if found.position is not None and found.position < len(origins):
            origin = origins[found.position]
            name = origin.meta.id or _ordinal(origin.meta.position)
            problems.append(f'{origin.source.path}: policy "{name}": {message}')
        else:
            problems.append(f"{kind} policies: {message}")
    try:
        return CompiledPolicies(text, [origin.meta.id for origin in origins])
    except CedarError as exc:  # parsed file by file already; a failure here is a join problem
        problems.append(f"{kind} policies: {exc}")
        return None


def _duplicates(sources: Sequence[_Source], problems: list[str]) -> None:
    where: dict[str, list[str]] = {}
    for source in sources:
        for meta in source.metas:
            if meta.id is not None:
                where.setdefault(meta.id, []).append(source.path)
    for identifier, paths in where.items():
        if len(paths) > 1:
            problems.append(f'policy id "{identifier}" is used more than once: {", ".join(paths)}')


def load_policies(root: Path, tenants: Collection[str], *, include_demo: bool = False) -> PolicySet:
    """Read, check and compile every policy under `root`. Raises PolicyLoadError, naming every
    problem, if anything is wrong; it never returns a partial set."""
    problems: list[str] = []
    tenant_ids = sorted(set(tenants))
    for tenant in tenant_ids:
        if tenant in SHARED_DIRS:
            problems.append(f"tenant id {tenant!r} is the name of a shared policy directory")
    if not root.is_dir():
        raise PolicyLoadError([f"the policy directory {root} does not exist"])

    schema_text = _read(root, root / SCHEMA_FILE, problems)
    schema: CedarSchema | None = None
    if schema_text is not None:
        try:
            schema = CedarSchema(schema_text)
        except CedarError as exc:
            problems.append(f"{SCHEMA_FILE}: {exc}")

    allowed = {DEFAULT_DIR, DEMO_DIR, *tenant_ids}
    for directory in _directories(root):
        if directory.name not in allowed:
            problems.append(
                f"{directory.name}/: not a policy directory; use default, demo or the id of a "
                f"configured tenant ({', '.join(tenant_ids) or 'none are configured'})"
            )
    if not (root / DEFAULT_DIR).is_dir():
        problems.append(f"{DEFAULT_DIR}/: missing, so no policy applies to every tenant")

    groups = [DEFAULT_DIR, *([DEMO_DIR] if include_demo else []), *tenant_ids]
    sources: list[_Source] = []
    files: list[PolicyFile] = []
    if schema_text is not None:
        files.append(PolicyFile(SCHEMA_FILE, schema_text))
    for group in groups:
        for kind, paths in _scan_group(root, group, problems).items():
            for path in paths:
                text = _read(root, path, problems)
                if text is None:
                    continue
                relative = _relative(path, root)
                files.append(PolicyFile(relative, text))
                try:
                    metas = tuple(read_policies(text))
                except CedarError as exc:
                    problems.append(f"{relative}: {exc}")
                    continue
                sources.append(_Source(relative, group, kind, text, metas))
    for source in sources:
        _check_source(source, problems)

    shared = [s for s in sources if s.group in SHARED_DIRS]
    compiled: dict[str, TenantPolicies] = {}
    for tenant in tenant_ids or [""]:
        own = [s for s in sources if s.group == tenant] if tenant else []
        mine = shared + own
        _duplicates(mine, problems)
        if schema is None:
            continue
        access = _validate("access", [s for s in mine if s.kind == "access"], schema, problems)
        approval = _validate(
            "approval", [s for s in mine if s.kind == "approval"], schema, problems
        )
        if tenant and access is not None and approval is not None:
            infos = tuple(
                PolicyInfo(meta.id, meta.effect, s.kind, s.path)
                for s in mine
                for meta in s.metas
                if meta.id is not None
            )
            compiled[tenant] = TenantPolicies(tenant, access, approval, infos)

    if problems or schema is None:
        raise PolicyLoadError(list(dict.fromkeys(problems)))
    ordered = tuple(sorted(files, key=lambda f: f.path))
    version = sha256_hex(canonical_json([[f.path, f.content] for f in ordered]))
    every = tuple(
        PolicyInfo(meta.id, meta.effect, s.kind, s.path)
        for s in sorted(sources, key=lambda s: s.path)
        for meta in s.metas
        if meta.id is not None
    )
    return PolicySet(version, schema, compiled, ordered, every)


class VersionRecorder(Protocol):
    async def record(self, policy_set: PolicySet) -> None: ...


@dataclass(frozen=True)
class ReloadResult:
    """The outcome of a reload. `version` is the one in force afterwards: the new one when `ok`,
    the old one when the new set was refused."""

    ok: bool
    version: str
    previous: str
    changed: bool
    errors: tuple[str, ...] = ()


class PolicyStore:
    """The policy set in force. A reload that fails changes nothing."""

    def __init__(
        self,
        root: Path,
        tenants: Collection[str],
        *,
        include_demo: bool = False,
        recorder: VersionRecorder | None = None,
    ) -> None:
        self.root = root
        self.tenants = tuple(sorted(set(tenants)))
        self.include_demo = include_demo
        self._recorder = recorder
        self._current: PolicySet | None = None
        self._lock = anyio.Lock()

    def load(self, root: Path | None = None) -> PolicySet:
        """Read and check the policies under `root` (the store's own by default) without
        changing what is in force."""
        return load_policies(root or self.root, self.tenants, include_demo=self.include_demo)

    def start(self) -> PolicySet:
        """The first load. Raises PolicyLoadError: with nothing in force yet there is no earlier
        set to keep, and starting without rules is not an option."""
        self._current = self.load()
        return self._current

    @property
    def current(self) -> PolicySet:
        if self._current is None:
            raise PolicyNotLoaded("no policy set is loaded")
        return self._current

    @property
    def version(self) -> str:
        return self.current.version

    async def record_current(self) -> None:
        """Write the version in force to the database (at startup)."""
        if self._recorder is not None:
            await self._recorder.record(self.current)

    async def reload(self) -> ReloadResult:
        async with self._lock:
            previous = self.current.version
            try:
                loaded = await anyio.to_thread.run_sync(self.load)
            except PolicyLoadError as exc:
                for problem in exc.problems:
                    log.error("policy_reload_refused", problem=problem, version=previous)
                return ReloadResult(False, previous, previous, False, exc.problems)
            except Exception:
                log.exception("policy_reload_failed", version=previous)
                return ReloadResult(
                    False, previous, previous, False, ("the policies could not be read",)
                )
            if self._recorder is not None:
                try:
                    await self._recorder.record(loaded)
                except Exception:
                    log.exception("policy_version_not_recorded", version=loaded.version)
                    return ReloadResult(
                        False, previous, previous, False, ("the new version could not be recorded",)
                    )
            self._current = loaded
            log.info(
                "policies_reloaded",
                version=loaded.version,
                previous=previous,
                changed=loaded.version != previous,
            )
            return ReloadResult(True, loaded.version, previous, loaded.version != previous)


async def reload_on_sighup(store: PolicyStore) -> None:
    """Reload the policies whenever this process gets SIGHUP. It runs until it is cancelled. Where
    the signal cannot be caught (a thread that is not the main one, which is where the tests run
    the app) it does nothing and returns."""
    try:
        with anyio.open_signal_receiver(signal.SIGHUP) as signals:
            async for _ in signals:
                result = await store.reload()
                if not result.ok:
                    log.error("policy_sighup_refused", version=result.version)
    except (NotImplementedError, RuntimeError, ValueError, OSError):
        log.debug("policy_sighup_unavailable")
