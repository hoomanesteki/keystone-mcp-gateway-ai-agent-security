import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from keystone.core.types import Principal
from keystone.registry.naming import check_upstream_id

CONFIG_ENV_VAR = "KEYSTONE_CONFIG"

# The defaults match the host ports in deploy/docker-compose.yml, so a bare `uv run` works
# against `make up-core` without any environment.
DEFAULT_DATABASE_URL = "postgresql+asyncpg://keystone:keystone@localhost:55432/keystone"
DEFAULT_REDIS_URL = "redis://localhost:56379/0"


class TenantConfig(BaseModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")
    name: str = Field(min_length=1)


class UpstreamConfig(BaseModel):
    """One upstream MCP server. The gateway checks that an http upstream has a tenant and a url
    when it starts, so a half-written entry loads here and fails there with a clear message."""

    id: str
    tenant: str | None = None
    transport: Literal["http", "builtin"] = "http"
    url: str | None = None

    @field_validator("id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        check_upstream_id(value)
        return value


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
