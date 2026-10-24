import os
import re
from decimal import Decimal
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
# How the rules' score and the model's make one (KS-792, ADR-0011): `rules_first` or `max`.
ScanJoin = Literal["rules_first", "max"]

# What the evaluation measured on the dev split (eval/detector/combine.py, ADR-0011), which are
# therefore the defaults. The model reads a long text in windows of this many tokens of the text
# (the two special tokens come on top), each sharing `WINDOW_OVERLAP` of them with the one before.
# Up to Phase 8 the windows were 510 and 64.
WINDOW_TOKENS = 128
WINDOW_OVERLAP = 64
# How much of the model's score counts for a text that the rules did not flag.
MODEL_WEIGHT = 0.7


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
    # How the score of the rules and the score of the model make one (ADR-0011). `rules_first`: a
    # text that the rules flag (their score is at `thresholds.suspicious` or more) keeps the rules'
    # score and is not given to the model; for any other text the model adds to the rules' score
    # at `model_weight` of its own, so on its own it can flag a text and never taint a session.
    # `max`: the higher of the two, and the model reads every text, which is what Phase 7 shipped.
    join: ScanJoin = "rules_first"
    model_weight: float = Field(default=MODEL_WEIGHT, gt=0, le=1)
    # The windows the model reads a long text in: tokens of the text in a window, and tokens shared
    # with the window before. A short window keeps an attack from being diluted by the document
    # around it, which is why the model is weak on documents; it also costs more windows for a text.
    window_tokens: int = Field(default=WINDOW_TOKENS, ge=16, le=510)
    window_overlap: int = Field(default=WINDOW_OVERLAP, ge=0)
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

    @model_validator(mode="after")
    def _windows_move_forward(self) -> "ScannerSettings":
        if self.window_overlap >= self.window_tokens:
            raise ValueError("window_overlap must be less than window_tokens")
        return self


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


class RateLimit(BaseModel):
    """One token bucket (KS-804): `capacity` calls at once, and `refill_per_s` more each second.
    A capacity under 1 would refuse every call."""

    model_config = ConfigDict(extra="forbid")

    capacity: float = Field(ge=1, le=1_000_000)
    refill_per_s: float = Field(gt=0, le=1_000_000)


class RateLimitSettings(BaseModel):
    """How fast calls may come, by who makes them. Every scope is optional, a scope that is not set
    has no limit, and a call is checked against all that are set. A virtual tool and a call that
    waits for approval count like any other, since they are calls."""

    model_config = ConfigDict(extra="forbid")

    # All the calls of a tenant, whoever makes them.
    per_tenant: RateLimit | None = None
    # The calls of one user (the token's `sub`), through any agent.
    per_user: RateLimit | None = None
    # The calls of one agent (the OAuth client), of every user.
    per_agent: RateLimit | None = None
    # The calls to one tool, from every user of the tenant: it protects the upstream behind it.
    per_tool: RateLimit | None = None

    def scopes(self) -> list[tuple[str, RateLimit]]:
        """The scopes that are set, in the order a call is checked."""
        found = (
            ("per_tenant", self.per_tenant),
            ("per_user", self.per_user),
            ("per_agent", self.per_agent),
            ("per_tool", self.per_tool),
        )
        return [(name, limit) for name, limit in found if limit is not None]


class BudgetConfig(BaseModel):
    """A spending limit (KS-805, ADR-0014): `limit_usd` for one tenant, user or agent over a day or
    a month, both counted in UTC. A call that would take the spend over it is refused before it
    runs. The file is the only source of budgets and is applied at startup: one that is not in it
    any more is removed."""

    model_config = ConfigDict(extra="forbid")

    tenant: str = Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")
    scope: Literal["tenant", "user", "agent"]
    # The user id (the token's `sub`) or the agent id (its `azp`). The tenant's own id, which a
    # budget for the tenant does not need to repeat.
    scope_id: str | None = Field(default=None, min_length=1, max_length=256)
    window: Literal["day", "month"]
    # Dollars. Read as the number it looks like (0.03 is three cents, not a nearby float).
    limit_usd: Decimal = Field(gt=0, max_digits=18, decimal_places=9)

    @model_validator(mode="after")
    def _the_id_of_the_scope(self) -> "BudgetConfig":
        if self.scope == "tenant":
            if self.scope_id not in (None, self.tenant):
                raise ValueError("a tenant budget has the tenant for its scope_id; leave it out")
            self.scope_id = self.tenant
        elif self.scope_id is None:
            raise ValueError(f"a {self.scope} budget needs a scope_id")
        return self


class LlmProviderSettings(BaseModel):
    """One model provider the proxy forwards to (KS-806)."""

    model_config = ConfigDict(extra="forbid")

    # Where the provider's API is. The proxy adds the path (/v1/messages, /v1/chat/completions).
    base_url: str
    # The environment variable that holds the provider's API key. Keystone reads it at startup and
    # stores the key in the vault, encrypted, as the static credential of `llm_anthropic` or
    # `llm_openai`. The key itself is never in this file.
    api_key_env: str | None = None

    @field_validator("base_url")
    @classmethod
    def _an_http_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("a provider's base_url must be an http or https URL")
        if parts.query or parts.fragment or parts.username or parts.password:
            raise ValueError("a provider's base_url has no credentials, query or fragment")
        return value.rstrip("/")

    @field_validator("api_key_env")
    @classmethod
    def _a_variable_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError(f"{value!r} is not a valid environment variable name")
        if value.upper().startswith("KEYSTONE_"):
            # Pointing the key at the master key would store Keystone's own secret as a credential.
            raise ValueError(f"{value} is Keystone's own setting and cannot be a provider key")
        return value


class LlmProxySettings(BaseModel):
    """The passthrough for model calls (KS-806, ADR-0016): the same identity, budget and tracing as
    a tool call. Off by default."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    # The tenant whose vault holds the provider keys, and so the tenant the proxy serves: an
    # upstream id is unique across tenants, and `llm_anthropic` can belong to one. With one tenant
    # in the config it is that one.
    tenant: str | None = None
    # The price list (pricing.example.yaml shows the shape). A relative path is read from the
    # working directory.
    pricing_file: Path = Path("pricing.yaml")
    # A model with no price is refused with a 400, unless this is on: then it is allowed, costs
    # nothing and a warning is logged.
    allow_unpriced: bool = False
    # The longest answer assumed when a request does not say (OpenAI's max_tokens is optional), for
    # the estimate a budget is checked against.
    default_max_tokens: int = Field(default=4096, ge=1, le=1_000_000)
    # The largest request body the proxy reads.
    max_body_bytes: int = Field(default=8 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    # How long the proxy waits on a provider for a byte, for a stream or a whole answer.
    timeout_s: float = Field(default=600.0, gt=0, le=3600)
    anthropic: LlmProviderSettings = Field(
        default_factory=lambda: LlmProviderSettings(
            base_url="https://api.anthropic.com", api_key_env="ANTHROPIC_API_KEY"
        )
    )
    openai: LlmProviderSettings = Field(
        default_factory=lambda: LlmProviderSettings(
            base_url="https://api.openai.com", api_key_env="OPENAI_API_KEY"
        )
    )


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
    # `passthrough` is the baseline of the red-team runs (KS-902, ADR-0017): the pipeline keeps its
    # order, its audit record and the credentials it adds for an upstream, and every other slot is
    # the Phase 1 stub that lets the call through; the scanner is not built. It exists to measure
    # what the other slots buy, and it is not a setting for a deployment.
    profile: Literal["full", "passthrough"] = "full"
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
    rate_limits: RateLimitSettings = Field(default_factory=RateLimitSettings)
    budgets: list[BudgetConfig] = Field(default_factory=list)
    llm_proxy: LlmProxySettings = Field(default_factory=LlmProxySettings)
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
    def _the_tenant_of_the_llm_proxy(self) -> "Settings":
        proxy = self.llm_proxy
        if not proxy.enabled:
            return self
        if proxy.tenant is None:
            if len(self.tenants) != 1:
                raise ValueError(
                    "llm_proxy.tenant must name the tenant whose vault holds the provider keys, "
                    "since the config does not list exactly one tenant"
                )
            self.llm_proxy = proxy.model_copy(update={"tenant": self.tenants[0].id})
        elif self.tenants and proxy.tenant not in {t.id for t in self.tenants}:
            raise ValueError(f"llm_proxy.tenant {proxy.tenant!r} is not in `tenants`")
        return self

    @model_validator(mode="after")
    def _a_budget_is_listed_once(self) -> "Settings":
        seen: set[tuple[str, str, str | None, str]] = set()
        for b in self.budgets:
            key = (b.tenant, b.scope, b.scope_id, b.window)
            if key in seen:
                raise ValueError(
                    f"the {b.window} budget of {b.scope} {b.scope_id!r} in tenant {b.tenant!r} "
                    "is listed twice"
                )
            seen.add(key)
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

    @model_validator(mode="after")
    def _passthrough_is_not_for_production(self) -> "Settings":
        if self.profile == "passthrough" and self.env == "prod":
            raise ValueError(
                "profile passthrough defends nothing and is not allowed when env is prod"
            )
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
