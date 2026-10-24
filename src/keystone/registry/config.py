"""The `upstreams` section of keystone.yaml, and how it reaches the database (plan section 3.9).

The YAML is the source of truth for config upstreams. At startup `apply_config_upstreams` checks
every entry, upserts it with `source=config`, and disables config upstreams that are no longer in
the file. It never deletes: audit records name upstreams, and a deleted row would leave them
pointing at nothing.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

import anyio
import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator

from keystone.core.types import Risk, ToolTag
from keystone.identity.vault import HEADER_NAME, Vault
from keystone.policy.extractors import check_extractors
from keystone.policy.schema_info import ArgField
from keystone.registry.naming import BUILTIN_UPSTREAM_IDS, check_upstream_id
from keystone.registry.repo import CredentialMode, UpstreamRepo, UpstreamSpec
from keystone.registry.ssrf import UnsafeUpstreamUrl, check_upstream_url

log = structlog.get_logger()

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# An image is given to `docker run` after the options, and a name that starts with a dash would be
# read as one.
_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}")


class ConfigError(ValueError):
    """The upstreams section cannot be applied. The message lists every problem found."""


class ToolOverride(BaseModel):
    """What an operator says about one tool. A field left out keeps the default (risk medium, no
    tags, no cost, the pipeline's timeout)."""

    model_config = ConfigDict(extra="forbid")

    risk: Risk | None = None
    tags: list[ToolTag] | None = None
    cost_per_call_usd: float | None = Field(default=None, ge=0)
    timeout_s: float | None = Field(default=None, gt=0)
    extract: dict[str, str] = Field(default_factory=dict)


class UpstreamConfig(BaseModel):
    """One upstream MCP server. Whether an http upstream has a tenant and a url is checked when
    the config is applied, so a half-written entry loads here and fails there with a clear
    message that names every problem at once."""

    # A misspelled key (`tool:` for `tools:`) must fail, not quietly do nothing.
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant: str | None = None
    # `builtin` is an upstream that Keystone runs itself: the sandbox (KS-802). `container_stdio` is
    # a stdio server that runs in a container with no network (KS-803, ADR-0012).
    transport: Literal["http", "stdio", "container_stdio", "builtin"] = "http"
    url: str | None = None
    # For stdio, the program and its arguments. For container_stdio, what runs in the container in
    # place of the image's own command (optional).
    command: list[str] | None = None
    # Environment for a stdio child, on top of PATH, or for the container of a container_stdio
    # one. Keystone's own environment is never passed. It holds settings, not secrets: this file is
    # not a secret store.
    env: dict[str, str] = Field(default_factory=dict)
    # container_stdio only: the image to run, which must be built on the host already, and whether
    # the container gets a network. `bridge` is a decision to let a third-party server reach out.
    image: str | None = None
    network: Literal["none", "bridge"] = "none"
    credential_mode: CredentialMode = "none"
    # Header name -> the environment variable that holds its value. At startup Keystone reads the
    # variables and stores them in the vault as the upstream's credential, so the secret is in the
    # environment or the vault and never in this file.
    credential_env: dict[str, str] = Field(default_factory=dict)
    tools: dict[str, ToolOverride] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        check_upstream_id(value)
        return value

    @field_validator("image")
    @classmethod
    def _an_image_name(cls, value: str | None) -> str | None:
        if value is not None and not _IMAGE.fullmatch(value):
            raise ValueError(f"image {value!r} is not a Docker image name such as img:1")
        return value

    @field_validator("env")
    @classmethod
    def _safe_env(cls, value: dict[str, str]) -> dict[str, str]:
        for name in value:
            if not _ENV_NAME.fullmatch(name):
                raise ValueError(f"{name!r} is not a valid environment variable name")
            if name.upper().startswith("KEYSTONE_"):
                # Copying Keystone's master key or database URL into a third-party server's
                # environment is the leak this key exists to prevent.
                raise ValueError(f"{name} is Keystone's own setting and cannot go to an upstream")
        return value

    @field_validator("credential_env")
    @classmethod
    def _safe_credential_env(cls, value: dict[str, str]) -> dict[str, str]:
        for header, variable in value.items():
            if not HEADER_NAME.fullmatch(header):
                raise ValueError(f"{header!r} is not a usable header name")
            if not _ENV_NAME.fullmatch(variable):
                raise ValueError(f"{variable!r} is not a valid environment variable name")
            if variable.upper().startswith("KEYSTONE_"):
                # Pointing a credential at the master key or the database URL would hand Keystone's
                # own secrets to a third party.
                raise ValueError(f"{variable} is Keystone's own setting and cannot be a credential")
        return value


def stdio_environments(upstreams: Sequence[UpstreamConfig]) -> dict[str, dict[str, str]]:
    """The environment each stdio upstream asks for, by upstream id."""
    return {u.id: dict(u.env) for u in upstreams if u.env}


def container_networks(upstreams: Sequence[UpstreamConfig]) -> dict[str, str]:
    """The network each containerized stdio upstream was given, by upstream id."""
    return {u.id: u.network for u in upstreams if u.transport == "container_stdio"}


def tool_overrides(upstreams: Sequence[UpstreamConfig]) -> dict[str, dict[str, ToolOverride]]:
    """Per-tool settings by upstream id, then by the upstream's own tool name."""
    return {u.id: dict(u.tools) for u in upstreams if u.tools}


@dataclass
class ConfigReport:
    """What applying the config did, by upstream id."""

    upserted: list[str] = field(default_factory=list)
    disabled: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


async def _problems(
    upstreams: Sequence[UpstreamConfig],
    tenant_ids: Collection[str],
    allow_private: bool,
    args: Mapping[str, ArgField] | None,
) -> list[str]:
    problems: list[str] = []
    seen: set[str] = set()
    for upstream in upstreams:
        name = f"upstream {upstream.id!r}"
        if upstream.id in seen:
            problems.append(f"{name} is listed twice")
        seen.add(upstream.id)
        if args is not None:
            for tool_name, override in upstream.tools.items():
                for problem in check_extractors(override.extract, args):
                    problems.append(f"{name} tool {tool_name!r}: {problem}")
        if upstream.transport == "builtin" and upstream.id not in BUILTIN_UPSTREAM_IDS:
            known = ", ".join(sorted(BUILTIN_UPSTREAM_IDS))
            problems.append(
                f"there is no built-in upstream named {upstream.id!r} (built in: {known})"
            )
        if upstream.tenant is None:
            problems.append(f"{name} needs a tenant")
        elif upstream.tenant not in tenant_ids:
            problems.append(f"{name} names tenant {upstream.tenant!r}, which is not in `tenants`")
        if upstream.transport == "builtin":
            continue
        if upstream.transport == "http":
            if upstream.url is None:
                problems.append(f"{name} needs a url")
                continue
            try:
                # Resolving a name blocks, so it runs off the event loop.
                await anyio.to_thread.run_sync(check_upstream_url, upstream.url, allow_private)
            except UnsafeUpstreamUrl as exc:
                problems.append(f"{name}: {exc}")
        elif upstream.transport == "container_stdio":
            if not upstream.image:
                problems.append(f"{name} needs an image")
            if upstream.url:
                problems.append(f"{name} is container_stdio, so `url` does not apply")
            for variable in upstream.env:
                if variable.upper().startswith("DOCKER_"):
                    # It would reconfigure the docker command that starts the container.
                    problems.append(
                        f"{name} passes {variable} to its container, and docker reads it too"
                    )
        elif not upstream.command:
            problems.append(f"{name} needs a command")
        if upstream.transport == "http" and (upstream.command or upstream.env):
            problems.append(f"{name} is http, so `command` and `env` do not apply")
        if upstream.image and upstream.transport != "container_stdio":
            problems.append(f"{name} is not container_stdio, so `image` does not apply")
        if upstream.credential_env and upstream.transport != "http":
            problems.append(f"{name} is not http, so it has no headers for `credential_env`")
        if upstream.credential_env and upstream.credential_mode == "none":
            problems.append(
                f"{name} has `credential_env` but credential_mode none, so it is never sent"
            )
    return problems


async def apply_config_upstreams(
    repo: UpstreamRepo,
    upstreams: Sequence[UpstreamConfig],
    tenant_ids: Collection[str],
    *,
    allow_private: bool = False,
    args: Mapping[str, ArgField] | None = None,
    builtins: Collection[str] = (),
) -> ConfigReport:
    """Make the database match the config. Raises ConfigError, before writing anything, when an
    entry is unusable. `args` are the fields of the schema's args record (KS-405): an `extract`
    key or spec that does not fit them is a problem. Without it the extractors are not checked.

    `builtins` are the ids of the built-in upstreams this process serves (the sandbox, when it is
    on). A built-in entry in the config is stored when its id is among them and is otherwise
    skipped, and a skipped one that was stored before is disabled with the other config upstreams
    that left the file: turning the sandbox off takes its tools away on the next start.
    """
    problems = await _problems(upstreams, tenant_ids, allow_private, args)
    if problems:
        raise ConfigError("; ".join(problems))

    report = ConfigReport()
    kept: set[str] = set()
    for upstream in upstreams:
        if upstream.transport == "builtin" and upstream.id not in builtins:
            report.skipped.append(upstream.id)
            continue
        if upstream.tenant is None:  # _problems has already refused this
            raise ConfigError(f"upstream {upstream.id!r} needs a tenant")
        spec = UpstreamSpec(
            id=upstream.id,
            tenant_id=upstream.tenant,
            transport=upstream.transport,
            url=upstream.url,
            command=upstream.command,
            image=upstream.image,
            credential_mode=upstream.credential_mode,
            source="config",
        )
        try:
            row = await repo.upsert(spec)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        if row.status == "disabled":
            # It was removed from the file once and is back. A fresh sync decides its status.
            await repo.set_status(upstream.id, "unknown")
        kept.add(upstream.id)
        report.upserted.append(upstream.id)

    for row in await repo.list(include_disabled=False):
        if row.source == "config" and row.id not in kept:
            await repo.set_status(row.id, "disabled")
            report.disabled.append(row.id)
            log.info("config_upstream_disabled", upstream=row.id)
    return report


async def seed_credentials(
    vault: Vault, upstreams: Sequence[UpstreamConfig], environ: Mapping[str, str]
) -> list[str]:
    """Store the credentials the config takes from the environment, through the vault. A variable
    that is not set leaves the stored credential as it is. Returns the ids it wrote. Call it after
    `apply_config_upstreams`, because a credential belongs to an upstream row."""
    written: list[str] = []
    for upstream in upstreams:
        if not upstream.credential_env or upstream.tenant is None:
            continue
        headers: dict[str, str] = {}
        for header, variable in upstream.credential_env.items():
            value = environ.get(variable, "")
            if value:
                headers[header] = value
            else:
                log.warning("credential_variable_not_set", upstream=upstream.id, variable=variable)
        if headers and await vault.seed(upstream.tenant, upstream.id, headers):
            written.append(upstream.id)
            log.info("credential_seeded", upstream=upstream.id, headers=sorted(headers))
    return written
