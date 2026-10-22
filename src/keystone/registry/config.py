"""The `upstreams` section of keystone.yaml, and how it reaches the database (plan section 3.9).

The YAML is the source of truth for config upstreams. At startup `apply_config_upstreams` checks
every entry, upserts it with `source=config`, and disables config upstreams that are no longer in
the file. It never deletes: audit records name upstreams, and a deleted row would leave them
pointing at nothing.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass, field
from typing import Literal

import anyio
import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator

from keystone.core.types import Risk, ToolTag
from keystone.registry.naming import check_upstream_id
from keystone.registry.repo import CredentialMode, UpstreamRepo, UpstreamSpec
from keystone.registry.ssrf import UnsafeUpstreamUrl, check_upstream_url

log = structlog.get_logger()


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
    transport: Literal["http", "stdio", "builtin"] = "http"
    url: str | None = None
    command: list[str] | None = None
    credential_mode: CredentialMode = "none"
    tools: dict[str, ToolOverride] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        check_upstream_id(value)
        return value


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
    upstreams: Sequence[UpstreamConfig], tenant_ids: Collection[str], allow_private: bool
) -> list[str]:
    problems: list[str] = []
    seen: set[str] = set()
    for upstream in upstreams:
        name = f"upstream {upstream.id!r}"
        if upstream.id in seen:
            problems.append(f"{name} is listed twice")
        seen.add(upstream.id)
        if upstream.transport == "builtin":
            continue
        if upstream.tenant is None:
            problems.append(f"{name} needs a tenant")
        elif upstream.tenant not in tenant_ids:
            problems.append(f"{name} names tenant {upstream.tenant!r}, which is not in `tenants`")
        if upstream.transport == "http":
            if upstream.url is None:
                problems.append(f"{name} needs a url")
                continue
            try:
                # Resolving a name blocks, so it runs off the event loop.
                await anyio.to_thread.run_sync(check_upstream_url, upstream.url, allow_private)
            except UnsafeUpstreamUrl as exc:
                problems.append(f"{name}: {exc}")
        elif not upstream.command:
            problems.append(f"{name} needs a command")
    return problems


async def apply_config_upstreams(
    repo: UpstreamRepo,
    upstreams: Sequence[UpstreamConfig],
    tenant_ids: Collection[str],
    *,
    allow_private: bool = False,
) -> ConfigReport:
    """Make the database match the config. Raises ConfigError, before writing anything, when an
    entry is unusable."""
    problems = await _problems(upstreams, tenant_ids, allow_private)
    if problems:
        raise ConfigError("; ".join(problems))

    report = ConfigReport()
    kept: set[str] = set()
    for upstream in upstreams:
        if upstream.transport == "builtin":
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
        if row.source == "config" and row.id not in kept and row.id not in report.skipped:
            await repo.set_status(row.id, "disabled")
            report.disabled.append(row.id)
            log.info("config_upstream_disabled", upstream=row.id)
    return report
