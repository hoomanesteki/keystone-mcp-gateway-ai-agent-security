import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from keystone.core.types import Principal
from keystone.registry.config import UpstreamConfig

CONFIG_ENV_VAR = "KEYSTONE_CONFIG"

# The defaults match the host ports in deploy/docker-compose.yml, so a bare `uv run` works
# against `make up-core` without any environment.
DEFAULT_DATABASE_URL = "postgresql+asyncpg://keystone:keystone@localhost:55432/keystone"
DEFAULT_REDIS_URL = "redis://localhost:56379/0"


class TenantConfig(BaseModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")
    name: str = Field(min_length=1)


class AgentConfig(BaseModel):
    """What the config says about one agent: the OAuth client that acts for users (KS-308). The
    key under `agents` is the client id, which a token carries in `azp`."""

    model_config = ConfigDict(extra="forbid")

    trust: Literal["low", "standard", "high"] = "standard"


class RegistrySettings(BaseModel):
    """How the registry keeps its tool list current (KS-203)."""

    model_config = ConfigDict(extra="forbid")

    # How often every upstream is synced. 0 turns the periodic sync off.
    sync_interval_s: float = Field(default=300.0, ge=0)
    # The longest one upstream's sync may take, connecting included.
    sync_timeout_s: float = Field(default=20.0, gt=0)
    # How long the gateway keeps its in-memory copy of a tenant's tools. A sync run by the CLI
    # reaches a running gateway after this long at most.
    cache_ttl_s: float = Field(default=2.0, ge=0)


class HealthSettings(BaseModel):
    """How the gateway watches its upstreams (KS-209)."""

    model_config = ConfigDict(extra="forbid")

    # Seconds between probes. 0 turns the probes off, and no upstream is ever marked down.
    interval_s: float = Field(default=30.0, ge=0)
    # A probe that takes longer than this has failed.
    timeout_s: float = Field(default=3.0, gt=0)
    # Consecutive failed probes before an upstream is `degraded`, and before it is `down`.
    degraded_after: int = Field(default=1, ge=1)
    down_after: int = Field(default=3, ge=1)

    @model_validator(mode="after")
    def _down_comes_last(self) -> "HealthSettings":
        if self.down_after < self.degraded_after:
            raise ValueError("down_after must be at least degraded_after")
        return self


# Host header values the MCP endpoint accepts. A browser on another site can be tricked into
# calling localhost, and its Host header then names that site (DNS rebinding).
DEFAULT_ALLOWED_HOSTS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]

# Phase 1 has no authentication. Until KS-304, every caller is this person.
DEV_PRINCIPAL = Principal(
    tenant_id="acme", user_id="olivia", groups=("operators",), agent_id="ops-agent"
)


class Settings(BaseSettings):
    """Typed settings. Environment variables beat the YAML file named by KEYSTONE_CONFIG."""

    model_config = SettingsConfigDict(
        env_prefix="KEYSTONE_",
        # KEYSTONE_REGISTRY__SYNC_INTERVAL_S=5 sets registry.sync_interval_s.
        env_nested_delimiter="__",
        extra="ignore",
        validate_by_name=True,
        validate_by_alias=True,
    )

    env: Literal["dev", "test", "prod"] = "dev"
    database_url: SecretStr = SecretStr(DEFAULT_DATABASE_URL)
    redis_url: SecretStr = SecretStr(DEFAULT_REDIS_URL)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    config_path: Path | None = Field(default=None, validation_alias=CONFIG_ENV_VAR)
    tenants: list[TenantConfig] = Field(default_factory=list)
    upstreams: list[UpstreamConfig] = Field(default_factory=list)
    # Off by default: an upstream URL that resolves to a loopback, private or link-local address
    # is refused (KS-202). Local compose and the tests turn it on: their upstreams are local.
    allow_private_upstreams: bool = False
    registry: RegistrySettings = Field(default_factory=RegistrySettings)
    health: HealthSettings = Field(default_factory=HealthSettings)
    # Who every caller is until real authentication arrives (KS-304). Never allowed in prod.
    dev_principal: Principal | None = None
    allowed_hosts: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_HOSTS))

    @model_validator(mode="after")
    def _dev_principal_only_outside_prod(self) -> "Settings":
        if self.env == "prod":
            if self.dev_principal is not None:
                raise ValueError("dev_principal is not allowed when env is prod")
        elif self.dev_principal is None:
            self.dev_principal = DEV_PRINCIPAL
        return self

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper_case_level(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Order is priority: init arguments, then environment, then the YAML file.
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings]
        init_kwargs = init_settings.init_kwargs  # type: ignore[attr-defined]
        explicit = init_kwargs.get("config_path") or init_kwargs.get(CONFIG_ENV_VAR)
        path = explicit or os.environ.get(CONFIG_ENV_VAR)
        if path:
            if not Path(path).is_file():
                raise FileNotFoundError(f"config file not found: {path}")
            sources.append(YamlConfigSettingsSource(settings_cls, yaml_file=path))
        return tuple(sources)
