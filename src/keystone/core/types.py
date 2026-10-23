"""The data every interceptor reads and writes. Plan section 3.6, verbatim.

Changing a field here needs a story that says so and an ADR (engineering note 7).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, SecretStr


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_LEVEL: dict[Risk, int] = {Risk.LOW: 1, Risk.MEDIUM: 2, Risk.HIGH: 3, Risk.CRITICAL: 4}


class ToolTag(StrEnum):
    READS_UNTRUSTED = "reads_untrusted"
    READS_SENSITIVE = "reads_sensitive"
    EXTERNAL_EFFECT = "external_effect"
    CODE_EXEC = "code_exec"


class ToolStatus(StrEnum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    DISABLED = "disabled"


class Principal(BaseModel, frozen=True):
    tenant_id: str
    user_id: str  # OIDC "sub"
    groups: tuple[str, ...] = ()
    agent_id: str  # OIDC "azp" or "client_id"
    agent_trust: Literal["low", "standard", "high"] = "standard"
    scopes: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()  # "admin", "approver"


class ToolRef(BaseModel, frozen=True):
    name: str  # exposed name "<upstream>__<tool>", matches ^[a-zA-Z0-9_-]{1,64}$
    upstream_id: str
    upstream_tool_name: str
    tenant_id: str
    description: str
    input_schema: dict[str, Any]
    risk: Risk = Risk.MEDIUM
    tags: frozenset[ToolTag] = frozenset()
    cost_per_call_usd: float = 0.0
    timeout_s: float = 30.0
    description_hash: str
    schema_hash: str
    status: ToolStatus = ToolStatus.ACTIVE
    extractors: dict[str, str] = {}  # context key -> JSONPath into arguments


class SessionState(BaseModel):
    session_id: str
    principal: Principal
    flags: set[ToolTag] = Field(default_factory=set)
    tainted: bool = False
    call_count: int = 0
    spent_usd: float = 0.0
    created_at: datetime


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Decision(BaseModel):
    effect: Effect
    reasons: list[str] = []  # policy ids, rule ids
    source: Literal["policy", "stub", "pinning", "rate_limit", "budget", "virtual"]
    policy_version: str | None = None
    evaluated_ms: float = 0.0


class ToolResult(BaseModel):
    content: list[dict[str, Any]]  # MCP content blocks
    structured_content: dict[str, Any] | None = None
    is_error: bool = False


class ScanResult(BaseModel):
    score: float  # 0..1, higher = more likely injection
    label: Literal["benign", "suspicious", "injection"]
    rule_hits: list[str] = []
    # "error" is the scan that could not be made: the rules raised and the output went through as
    # it was (KS-703, ADR-0011). It was added to the plan's four so that the audit record can say
    # so.
    action: Literal["pass", "annotate", "redact", "block", "error"]
    model: str | None = None
    latency_ms: float = 0.0


class CallContext(BaseModel):
    call_id: str  # ULID
    received_at: datetime
    principal: Principal
    session: SessionState
    tool: ToolRef
    arguments: dict[str, Any]
    extracted: dict[str, int | str | bool] = {}
    upstream_headers: dict[str, SecretStr] = {}  # set by CredentialInterceptor, never serialized
    decision: Decision | None = None
    approval_id: str | None = None
    result: ToolResult | None = None
    scan: ScanResult | None = None
    cost_usd: float = 0.0
    dispatched: bool = False
    timings_ms: dict[str, float] = {}
