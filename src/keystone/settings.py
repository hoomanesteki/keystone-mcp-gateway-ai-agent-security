import os
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
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


class AuthSettings(BaseModel):
    """How callers are identified."""

    model_config = ConfigDict(extra="forbid")

    # "oidc": every request to /mcp carries a bearer token from the identity provider. "none":
    # every caller is `dev_principal`, which is only allowed when env is dev or test.
    mode: Literal["oidc", "none"] = "oidc"
    # An agent that is not listed under `agents` is refused with 403. With this on it gets in with
    # trust `low` instead.
    allow_unknown_agents: bool = False


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


class PolicySettings(BaseModel):
    """Where the policies are and which of them apply (KS-403)."""

    model_config = ConfigDict(extra="forbid")

    # The directory with schema.cedarschema, default/, one directory per tenant and demo/. A
    # relative path is read from the working directory.
    root: Path = Path("policies")
    # Also read demo/, the policies that go with the demo upstreams (transfers over 500 need
    # approval). Off by default: a deployment that is not the demo does not want them.
    include_demo: bool = False
    # How long the list of tools a caller may see is kept, per caller and policy version. A reload
    # changes the version, so it never serves an answer from the old rules.
    list_cache_ttl_s: float = Field(default=60.0, ge=0)


class AuditSettings(BaseModel):
    """What the gateway does when the audit log cannot be written (KS-501)."""

    model_config = ConfigDict(extra="forbid")

    # True: while the audit writer is unhealthy, every call is refused before it runs, because an
    # action with no record is what an audit log exists to prevent. Unset means true, except when
    # env is dev, where a stopped Postgres should not stop the demo.
    fail_closed: bool | None = None
    # Argument keys whose values are replaced in the log, besides the ones that look like secrets
    # (secret, token, password, api key, authorization). Compared whole, without regard to case.
    redact_keys: list[str] = Field(default_factory=list)


class ApprovalSettings(BaseModel):
    """How a call that needs a person's approval is held (KS-601, ADR-0010)."""

    model_config = ConfigDict(extra="forbid")

    # How long a call that needs approval is held in line before the agent gets KS_APPROVAL_PENDING
    # and an id to wait on with keystone__await_approval. Most requests in a staffed queue are
    # decided in under a minute, so the agent sees a slow call. 0 never holds a call. An HTTP
    # request that waits much longer than a few minutes meets timeouts nobody here controls.
    wait_seconds: float = Field(default=60.0, ge=0, le=300)
    # How long a request can be decided and used, counted from the request.
    ttl_seconds: float = Field(default=900.0, gt=0, le=7 * 24 * 3600)
    # Seconds between marking requests that ran out of time as expired. Nothing depends on it for
    # safety (a decision or a use of an expired request is refused either way); it keeps the
    # queue, the pending gauge and the waiting calls current.
    sweep_interval_s: float = Field(default=30.0, gt=0)
    # Seconds between looks at a request that a waiter is waiting for, when no message from Redis
    # woke it first.
    poll_interval_s: float = Field(default=2.0, gt=0)
    # Where a new request is announced (KS-604): a JSON body signed with the secret in
    # KEYSTONE_APPROVALS_WEBHOOK_SECRET, which is never read from this file, and a plain message to
    # a Slack incoming webhook. Neither delays the call. The Slack address is a secret in itself, so
    # it is better set from the environment (KEYSTONE_APPROVALS__SLACK_WEBHOOK_URL).
    webhook_url: str | None = None
    slack_webhook_url: SecretStr | None = None
    # Seconds before each retry of a delivery that failed; the number of values is the number of
    # retries. Three, 1 s then 2 s then 4 s, unless a test wants them quick.
    webhook_backoff_s: list[float] = Field(default_factory=lambda: [1.0, 2.0, 4.0])

    @field_validator("webhook_url", "slack_webhook_url", mode="before")
    @classmethod
    def _an_http_url(cls, value: object) -> object:
        """Checked before the value can be a SecretStr, and without echoing it: the address of a
        Slack webhook is a secret."""
        if value in (None, ""):
            return None
        text = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        parts = urlsplit(text)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("a webhook address must be an http or https URL")
        return value

    @field_validator("webhook_backoff_s")
    @classmethod
    def _delays(cls, value: list[float]) -> list[float]:
        if len(value) > 10 or any(delay < 0 or delay > 300 for delay in value):
            raise ValueError("webhook_backoff_s takes at most 10 delays of 0 to 300 seconds")
        return value


class ScannerThresholds(BaseModel):
    """Where a score becomes `suspicious` and where it becomes `injection`. A score on a threshold
    takes the higher label."""

    model_config = ConfigDict(extra="forbid")

    suspicious: float = Field(default=0.5, ge=0, le=1)
    injection: float = Field(default=0.85, ge=0, le=1)

    @model_validator(mode="after")
    def _in_order(self) -> "ScannerThresholds":
        if self.suspicious > self.injection:
            raise ValueError("thresholds.suspicious must not be above thresholds.injection")
        return self


HOST = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


Classifier = Literal["protectai-deberta-v2", "prompt-guard-2-86m", "none"]
ScanAction = Literal["pass", "annotate", "redact", "block"]


class ScannerActions(BaseModel):
    """What is done to an output that scored `suspicious` or `injection`, by the risk of the tool
    that made it (KS-703). `pass` leaves it alone and still records the score."""

    model_config = ConfigDict(extra="forbid")

    low: ScanAction = "annotate"
    medium: ScanAction = "annotate"
    high: ScanAction = "redact"
    critical: ScanAction = "block"


class ScannerSettings(BaseModel):
    """How tool output is checked for instructions aimed at the model (KS-701, KS-702)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    # The model behind the rules, or `none`. It needs the extra `keystone[scanner]`; without it the
    # scanner runs on its rules alone and logs that once at start. `prompt-guard-2-86m` needs the
    # Llama license accepted on Hugging Face.
    classifier: Classifier = "protectai-deberta-v2"
    # The longest a scan waits for the model. A model that has not answered by then is left out
    # of that scan, which is then scored by the rules alone (`model` says "timeout").
    classifier_timeout_ms: int = Field(default=300, ge=1, le=10_000)
    thresholds: ScannerThresholds = Field(default_factory=ScannerThresholds)
    actions: ScannerActions = Field(default_factory=ScannerActions)
    # Hosts a markdown image may point to without a mark against it. An image anywhere else, or any
    # markdown link or image with a long query string, is how a conversation leaves in a URL.
    allowed_domains: list[str] = Field(default_factory=list)
    # The most text one scan reads. A longer text is read at both ends, half of this at each, and
    # the scan says it was cut. Python regular expressions hold the interpreter while they run, so
    # the size of a scan is also the time the gateway is busy with it.
    max_scan_chars: int = Field(default=200_000, ge=1_000, le=50_000_000)
    # A new tool whose description, or the description of a field of its input schema, scores this
    # much or more with the rules is held until a person has read it (KS-706). It is apart from the
    # thresholds above: a person reads a description once, and an output is read on every call.
    description_threshold: float = Field(default=0.5, gt=0, le=1)

    @field_validator("allowed_domains")
    @classmethod
    def _bare_hosts(cls, value: list[str]) -> list[str]:
        """Host names only, in lower case, with no scheme, port or path: `cdn.acme.test`. A name
        also covers its subdomains. A leading dot is allowed and dropped."""
        hosts = [item.strip().lower().removeprefix(".") for item in value]
        if not all(HOST.match(host) for host in hosts):
            raise ValueError("allowed_domains takes host names such as cdn.acme.test")
        return hosts


IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}$")
RUNTIME_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


class SandboxSettings(BaseModel):
    """Where the code an agent writes runs (KS-801, ADR-0012). The limits of a container are not
    settings: they are in `keystone.sandbox.runner` and a deployment cannot loosen them."""

    model_config = ConfigDict(extra="forbid")

    # false leaves the `sandbox` upstream unregistered, and nothing then talks to Docker. A
    # deployment with no Docker socket (a Fargate task) sets it to false. KEYSTONE_SANDBOX_ENABLED
    # is the short name for it.
    enabled: bool = True
    # The image the code runs in: deploy/sandbox/Dockerfile.python, built by `make sandbox-image`.
    image: str = "keystone-sandbox-python:dev"
    # `runc`, or `runsc` where gVisor is installed. The name is one the Docker daemon knows.
    runtime: str = "runc"
    # How long one run may take before its container is killed. A tool's own timeout is this plus
    # ten seconds, so that a run that ran out of time is a result and not a failed call.
    timeout_s: float = Field(default=30.0, gt=0, le=300)
    # Containers running at once. A call over this waits for one to end.
    max_concurrent: int = Field(default=4, ge=1, le=64)

    @field_validator("image")
    @classmethod
    def _an_image_name(cls, value: str) -> str:
        if not IMAGE_REFERENCE.fullmatch(value):
            raise ValueError(
                "image must be a Docker image name, such as keystone-sandbox-python:dev"
            )
        return value

    @field_validator("runtime")
    @classmethod
    def _a_runtime_name(cls, value: str) -> str:
        if not RUNTIME_NAME.fullmatch(value):
            raise ValueError("runtime must be the name of a Docker runtime, such as runc or runsc")
        return value


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

# Who every caller is when `auth.mode` is `none`, which only dev and test allow.
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
        # A value that fails a check is not printed in the error. The setting may be a secret that
        # was put where it does not belong (a webhook secret in the YAML), or an address that is
        # one (Slack's), and a refusal should not be what publishes it.
        hide_input_in_errors=True,
    )

    env: Literal["dev", "test", "prod"] = "dev"
    database_url: SecretStr = SecretStr(DEFAULT_DATABASE_URL)
    # Where migrations connect, when that is not `database_url`. The application runs as a role
    # that may only add audit records (KS-503), and creating tables takes the role that owns them.
    # Without it, migrations use `database_url`.
    migrate_database_url: SecretStr | None = None
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
    audit: AuditSettings = Field(default_factory=AuditSettings)
    approvals: ApprovalSettings = Field(default_factory=ApprovalSettings)
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    # A short name for `scanner.classifier`, so that KEYSTONE_SCANNER_CLASSIFIER=none turns the
    # model off without the nested spelling (KEYSTONE_SCANNER__CLASSIFIER). It wins when both are
    # set, because it is the one a person types to change a running stack.
    scanner_classifier: Classifier | None = None
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    # A short name for `sandbox.enabled`, so that KEYSTONE_SANDBOX_ENABLED=false turns the sandbox
    # off without the nested spelling (KEYSTONE_SANDBOX__ENABLED). It wins when both are set.
    sandbox_enabled: bool | None = None
    policy: PolicySettings = Field(default_factory=PolicySettings)
    agents: dict[str, AgentConfig] = Field(default_factory=dict)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    # Token validation (KS-303). `oidc_issuer` is the value tokens carry in `iss`. Keystone reads
    # the identity provider's discovery document from there too, unless `oidc_discovery_url` names
    # another address: in compose, tokens name http://localhost:8180 and Keystone asks
    # http://keycloak:8080.
    oidc_issuer: str | None = None
    oidc_audience: str = "keystone"
    oidc_discovery_url: str | None = None
    # The one origin a browser may call the admin API from (the console, KS-605). CORS refuses any
    # other.
    console_origin: str = "http://localhost:5173"
    # Where traces go: an OTLP/HTTP endpoint such as http://jaeger:4318 (KS-504). Without it no
    # spans are made, and audit rows carry no trace id.
    otlp_endpoint: str | None = None
    # The address clients use to reach Keystone, for the sign-in metadata (RFC 9728). Without it
    # the address of the request is used.
    public_base_url: str | None = None
    # Fernet keys for the credential vault, comma separated: the first encrypts and every one
    # decrypts (KS-305). They are checked when the vault is built, not here, because a validation
    # error would print the value it rejected.
    master_keys: SecretStr | None = None
    # Who every caller is when `auth.mode` is `none`. It exists only then.
    dev_principal: Principal | None = None
    allowed_hosts: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_HOSTS))

    @property
    def audit_fail_closed(self) -> bool:
        """Whether an unhealthy audit writer stops calls: `audit.fail_closed`, or true unless env
        is dev."""
        configured = self.audit.fail_closed
        return configured if configured is not None else self.env != "dev"

    @model_validator(mode="after")
    def _the_short_name_of_the_classifier(self) -> "Settings":
        if self.scanner_classifier is not None:
            self.scanner = self.scanner.model_copy(update={"classifier": self.scanner_classifier})
        return self

    @model_validator(mode="after")
    def _the_short_name_of_the_sandbox_switch(self) -> "Settings":
        if self.sandbox_enabled is not None:
            self.sandbox = self.sandbox.model_copy(update={"enabled": self.sandbox_enabled})
        return self

    @model_validator(mode="after")
    def _dev_principal_only_without_authentication(self) -> "Settings":
        if self.auth.mode == "none":
            if self.env not in ("dev", "test"):
                raise ValueError("auth.mode none is only allowed when env is dev or test")
            if self.dev_principal is None:
                self.dev_principal = DEV_PRINCIPAL
        elif self.dev_principal is not None:
            raise ValueError("dev_principal needs auth.mode none")
        return self

    @field_validator("oidc_issuer", "oidc_discovery_url", "public_base_url", "otlp_endpoint")
    @classmethod
    def _http_url(cls, value: str | None, info: ValidationInfo) -> str | None:
        if not value:
            return None
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError(f"{info.field_name} must be an http or https URL")
        return value.rstrip("/") if info.field_name == "public_base_url" else value

    @field_validator("console_origin")
    @classmethod
    def _an_origin(cls, value: str) -> str:
        """scheme://host[:port] and nothing after it: that is what a browser sends as Origin."""
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.path not in ("", "/"):
            raise ValueError("console_origin must look like http://localhost:5173")
        if parts.query or parts.fragment or parts.username or parts.password:
            raise ValueError("console_origin must look like http://localhost:5173")
        return f"{parts.scheme}://{parts.netloc}"

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
