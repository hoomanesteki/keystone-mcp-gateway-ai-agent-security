# Runbook

How to run the local stack and what each part listens on. This file grows with the phases.

## Local stack

`make up` builds and starts Postgres, Redis, Keycloak, Jaeger, Prometheus, Grafana, the four demo
upstreams and Keystone, and waits until every container reports healthy. Cold start takes about
30 seconds on a laptop with warm images. The first build of the two local images takes longer.

| Command | What it does |
|---|---|
| `make up` | Start the full stack and wait for health |
| `make up-core` | Start Postgres and Redis only (what `make check` needs) |
| `make demo` | `make up`, reset the upstreams, run the scripted agent through Keystone as olivia and print its transcript |
| `make down` | Stop the stack and keep its data |
| `make reset` | Stop the stack and delete its volumes |
| `scripts/get_token.sh alice support-agent` | Print an access token for a Keycloak user (see Identity) |
| `make test-e2e` | The end-to-end tests against the running stack. The nightly workflow runs `make up` and then this |
| `bash scripts/smoke/phase_0.sh` | Print one health row per service |
| `bash scripts/smoke/phase_1.sh` | The body of `make demo`; exits 1 if a step fails or the audit count is off |
| `bash scripts/smoke/phase_3.sh` | Tokens for alice and bob, a request without a token (401), alice's 15 tools, bob's 3 globex tools and `KS_TOOL_NOT_FOUND` for an acme tool, the mail server's `api_key_received`, and a search of the Keystone logs for the demo keys and the master key. About 15 seconds. |
| `bash scripts/smoke/phase_2.sh` | Lists the 15 tools, quarantines and approves a changed echo description, stops the bank server and checks the refusal. About 45 seconds. It restarts Keystone with a 2 s health probe (`SMOKE_HEALTH_INTERVAL_S`) and restores everything when it ends. |

## Host ports

The defaults are in `.env.example`. Copy it to `.env` to move a port, then run `make up` again.
Tests never use these ports. They start their own services on free ports.

| Service | Host port | Notes |
|---|---|---|
| Keystone | 8080 | compose service `keystone` (or `keystone serve`). MCP endpoint: `http://localhost:8080/mcp` |
| Postgres | 55432 | database, user and password are all `keystone` |
| Redis | 56379 | tests use db 15 |
| Keycloak | 8180 | admin console login `admin` / `admin`, realm `keystone` |
| Jaeger UI | 16686 | |
| OTLP gRPC / HTTP | 4317 / 4318 | sent to Jaeger |
| Prometheus | 9090 | |
| Grafana | 3000 | login `admin` / `admin`, Prometheus and Jaeger provisioned |
| Mail, files, bank, echo | 8101, 8102, 8103, 8104 | demo upstreams, services `mail-mcp`, `files-mcp`, `bank-mcp`, `echo-mcp` |
| Files for globex | 8112 | the globex tenant's own drive, service `files-globex-mcp` |
| Web | 8105 | later phase |
| Fake LLM | 8199 | later phase |
| Console | 5173 | later phase |

The credentials above are for local development only. Nothing in compose is meant to be exposed
beyond the machine.

## Demo upstreams

Four small MCP servers give the gateway something to proxy and give tests state to inspect. They
share one image (`deploy/Dockerfile.upstreams`), and `make up` starts them.

| Server | Port | Tools |
|---|---|---|
| mail | 8101 | `list_emails`, `read_email`, `send_email` (12 seeded emails) |
| files | 8102 | `list_files`, `read_file`, `write_file` (confined to one workspace) |
| bank | 8103 | `get_balance`, `list_transactions`, `transfer` (3 seeded accounts) |
| echo | 8104 | `echo`, `sleep`, `fail` |
| files (globex) | 8112 | the tools of `files`, on another drive (`examples/fixtures/files-globex`), for the globex tenant |

Each also serves plain HTTP routes next to `/mcp` that are not tools, so an agent cannot call them:
`GET /healthz`, `POST /_reset` (back to the seed) and `GET /_state` (sent mail, transfers, written
files and the names of the tools called). The echo server adds `POST /_mutate`, which rewrites the
`echo` description, and `ECHO_POISONED=1`, which adds a tool with an injected description.

Run one outside compose: `uv run python -m examples.upstreams.mail_server --port 8101`. Add
`--transport stdio` to speak MCP over stdin and stdout.

| Variable | Purpose |
|---|---|
| `MAIL_DB`, `BANK_DB`, `FILES_DB` | SQLite file for the server's state. Default: a temp file. Every start re-seeds it. |
| `FILES_WORKSPACE` | Directory the files server confines itself to. Default: a temp directory. |
| `FILES_SEED` | Directory the files server starts from and returns to on reset. Default: `examples/fixtures/files`. |
| `MAIL_API_KEY`, `FILES_API_KEY`, `BANK_API_KEY`, `ECHO_API_KEY` | When set, `/mcp` requires a matching `X-Api-Key` header, and `/_state` reports `api_key_received`. Compose sets them (the defaults are in `.env.example`); Keystone takes them from its own environment and stores them in the vault. |
| `ECHO_POISONED` | `1` adds the poisoned tool. |

## Identity (Keycloak)

`make up` starts Keycloak 26 and imports the realm `keystone` from `deploy/keycloak/realm-keystone.json`.
Its admin console is at `http://localhost:8180` (`admin` / `admin`).

| User | Tenant | Groups | Realm role | Signs in through |
|---|---|---|---|---|
| `alice` | acme | `/tenants/acme`, `/support` | | `support-agent` |
| `olivia` | acme | `/tenants/acme`, `/operators` | | `ops-agent` |
| `lena` | acme | `/tenants/acme`, `/approvers` | `approver` | `keystone-cli` |
| `bob` | globex | `/tenants/globex` | | `support-agent` |
| `root` | acme | `/tenants/acme`, `/admins` | `admin` | `ops-agent` |

The user id is the user name, so a token's `sub` reads `alice`. Passwords are `<name>-dev-password`.
The clients `support-agent`, `ops-agent` and `keystone-cli` are confidential and allow the
password grant, which exists for the demo and the smoke scripts. `console` is public and uses
PKCE with the redirect `http://localhost:5173/*`. Every client puts `keystone` in `aud` and adds
the claims `tenant` (from the user attribute), `groups` (full paths such as `/tenants/acme`) and
`roles` (realm roles).

```bash
scripts/get_token.sh alice support-agent        # prints an access token
```

The script reads `<USER>_PASSWORD` and `<CLIENT>_SECRET` from the environment, then `.env`, then
`.env.example`. Those files hold development values that are public in this repository. Never use
them outside your own machine. The realm file contains `${NAME}` placeholders and no secrets;
Keycloak fills them from its environment, which `deploy/docker-compose.yml` sets.

A user needs an email, a first name, a last name, `emailVerified: true` and no required actions,
or Keycloak 26 refuses the password grant with "Account is not fully set up". A custom user
attribute such as `tenant` must be declared in the realm's user profile (the realm file does) or
the realm must set `unmanagedAttributePolicy` to `ENABLED`.

### The issuer

A token's `iss` must be the same whichever address asked for the token, or validation fails for
somebody. Compose sets `KC_HOSTNAME=http://localhost:8180` and `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`.
Every token then carries `iss=http://localhost:8180/realms/keystone`, while a request to
`http://keycloak:8080/...` from another container gets a `jwks_uri` that points at
`keycloak:8080`. A service inside the network can then fetch the keys without going out through
the host. `tests/e2e/test_keycloak.py` checks both answers.

Keystone has two settings for this. `oidc_issuer` (`KEYSTONE_OIDC_ISSUER`) is the value tokens
carry in `iss`: `http://localhost:8180/realms/keystone` in compose. `oidc_discovery_url`
(`KEYSTONE_OIDC_DISCOVERY_URL`) is where Keystone reads the discovery document, and it only needs
to be set when that differs from the issuer's own address: in compose it is
`http://keycloak:8080/realms/keystone/.well-known/openid-configuration`. The document's `issuer`
must equal `oidc_issuer`, or Keystone refuses its keys (503, and a log line naming both values).

### How Keystone checks a token

`identity/jwt.py` does it in this order, and stops at the first failure:

1. The header is read without verifying anything. An `alg` other than `RS256` or `ES256` is
   refused here, so `none`, the HMAC algorithms and anything else never reach a key. A header with
   `jku`, `jwk`, `x5u`, `crit` or `b64` is refused too, and so is a token without a `kid`.
2. The `kid` selects one key from the identity provider's published set. Encryption keys
   (`use: enc`), RSA keys under 2048 bits and EC keys that are not P-256 are not used.
3. The key must match the algorithm: RSA for `RS256`, EC P-256 for `ES256`.
4. The signature and the claims are verified with exactly that one algorithm. `exp`, `iat`,
   `iss`, `aud` and `sub` must be present. `iss` must equal the configured issuer, `aud` must
   contain the configured audience, and `exp`, `nbf` and `iat` get 60 seconds of leeway.

The keys are fetched from the discovery document with a 3 second timeout and kept in memory. A
token with an unknown `kid` makes Keystone fetch them again, at most once a minute, so a rotation
is picked up and a stream of made-up key ids costs the identity provider one request a minute.
While Keystone holds no keys at all, a failed fetch is retried after 2 seconds. If the keys cannot
be fetched, the answer is 503, not 401: the token was not shown to be bad.

`tenant` is required and must look like a tenant id. The agent is `azp`, or `client_id` when
there is no `azp`. Groups lose their leading `/`, and the `/tenants/...` groups are dropped,
because the tenant has its own claim. The roles come from `roles`, or from `realm_access.roles`
when there is no `roles` claim, and only `admin` and `approver` are kept.

### Agents

An agent is the OAuth client that acts for a user (`azp`). The `agents` section of the config
lists the ones that may connect and how far Keystone trusts each (`low`, `standard` or `high`):

```yaml
agents:
  support-agent: {trust: standard}
  ops-agent: {trust: high}
auth:
  allow_unknown_agents: false   # true lets an unlisted agent in with trust low
```

A token from an agent that is not listed is refused with 403, after it has been validated. Set
`KEYSTONE_AUTH__ALLOW_UNKNOWN_AGENTS=true` to let such an agent in with trust `low` instead.
`keystone agent list` prints the table and says which of the two applies. The trust level is in
the principal that policy sees (Phase 4).

### Changing the realm

Keycloak imports the realm file only when the realm does not exist. The development database
lives in the Keycloak container, so removing the container removes the realm. After you edit
`realm-keystone.json`:

| What you run | Result |
|---|---|
| `make reset && make up` | The edited realm is imported. This also deletes the Postgres, Prometheus and Grafana volumes. |
| `make down && make up` | The same for the realm, and the volumes stay. |
| `make up` alone | Nothing changes: the container is reused and the realm already exists. |
| `docker compose -f deploy/docker-compose.yml up -d --force-recreate keycloak` | Re-imports the file and touches nothing else. |

Recreating Keycloak creates new signing keys, so tokens fetched before it stop validating.
Keystone picks up the new keys the first time it sees a token with an unknown key id, at most once
a minute, so a token fetched right after the restart may be refused for up to a minute.

## Keystone settings

Environment variables win over the YAML file named by `KEYSTONE_CONFIG`.

| Variable | Default | Purpose |
|---|---|---|
| `KEYSTONE_ENV` | `dev` | `dev`, `test` or `prod` |
| `KEYSTONE_DATABASE_URL` | `postgresql+asyncpg://keystone:keystone@localhost:55432/keystone` | Postgres DSN |
| `KEYSTONE_REDIS_URL` | `redis://localhost:56379/0` | Redis URL. Session state lives here. Set it to an empty string to keep session state in the gateway process instead (one process only, lost on restart). |
| `KEYSTONE_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL` |
| `KEYSTONE_CONFIG` | unset | Path to a YAML file with the same keys |
| `KEYSTONE_ALLOWED_HOSTS` | `["127.0.0.1:*","localhost:*","[::1]:*"]` | JSON list of `Host` header values the MCP endpoint accepts (DNS rebinding guard). `:*` matches any port. Add the service name, for example `keystone:*`, to reach it from another container. |
| `KEYSTONE_ALLOW_PRIVATE_UPSTREAMS` | `false` | When `false`, an upstream URL whose host resolves to a loopback, private (RFC 1918), link-local (including 169.254.169.254), CGNAT (100.64.0.0/10) or IPv6 unique-local address is refused. Local compose sets it to `true`, because the demo upstreams are on a private network. |
| `KEYSTONE_REGISTRY__SYNC_INTERVAL_S` | `300` | Seconds between syncs of every upstream. `0` turns the timer off (the startup sync and the CLI still run). Also `registry.sync_interval_s` in the YAML. |
| `KEYSTONE_REGISTRY__SYNC_TIMEOUT_S` | `20` | The longest one upstream's sync may take, connecting included. |
| `KEYSTONE_REGISTRY__CACHE_TTL_S` | `2` | How long the gateway keeps its in-memory copy of a tenant's tools. A sync run by the CLI reaches a running gateway after this long at most. |
| `KEYSTONE_HEALTH__INTERVAL_S` | `30` | Seconds between health probes of every upstream. `0` turns them off, and no upstream is then marked down. Also `health.interval_s` in the YAML. |
| `KEYSTONE_HEALTH__TIMEOUT_S` | `3` | A probe slower than this has failed. |
| `KEYSTONE_HEALTH__DEGRADED_AFTER` | `1` | Consecutive failed probes before an upstream is `degraded`. |
| `KEYSTONE_HEALTH__DOWN_AFTER` | `3` | Consecutive failed probes before it is `down`. Not less than `DEGRADED_AFTER`. |
| `KEYSTONE_AUTH__MODE` | `oidc` | `oidc`: every request to `/mcp` carries a bearer token from the identity provider. `none`: every caller is the dev principal. `none` is refused unless `KEYSTONE_ENV` is `dev` or `test`. Also `auth.mode` in the YAML. |
| `KEYSTONE_OIDC_ISSUER` | unset | The `iss` of valid tokens. Required when the mode is `oidc`, and an https URL when `KEYSTONE_ENV=prod`. |
| `KEYSTONE_OIDC_AUDIENCE` | `keystone` | The value `aud` must contain. |
| `KEYSTONE_OIDC_DISCOVERY_URL` | the issuer's own `/.well-known/openid-configuration` | Where to read the discovery document, when that is not the issuer's address. See "The issuer". |
| `KEYSTONE_PUBLIC_BASE_URL` | the address of the request | How clients reach Keystone, for the sign-in metadata (`http://localhost:8080` in compose). Set it behind a proxy that changes the scheme or the host. |
| `KEYSTONE_MASTER_KEYS` | unset | Fernet keys for the credential vault, comma separated. The first encrypts, all decrypt. Needed by `keystone cred ...` and, from KS-306, by the gateway. |
| `KEYSTONE_DEV_PRINCIPAL` | tenant `acme`, user `olivia`, groups `operators`, agent `ops-agent` | JSON object. Who every caller is when `KEYSTONE_AUTH__MODE=none`. Refused in any other mode. |
| `KEYSTONE_AUTH__ALLOW_UNKNOWN_AGENTS` | `false` | Let an agent that is not under `agents` in with trust `low`. Also `auth.allow_unknown_agents` in the YAML. |
| `KEYSTONE_POLICY__ROOT` | `policies` | The directory with the schema and the policies (see Policies). A relative path is read from the working directory; the image has its own copy at `/app/policies`, and compose mounts this checkout's at `/etc/keystone/policies`. Also `policy.root` in the YAML. |
| `KEYSTONE_POLICY__INCLUDE_DEMO` | `false` | Also read `demo/`, the rules that go with the demo upstreams. Compose turns it on. |
| `KEYSTONE_POLICY__LIST_CACHE_TTL_S` | `60` | How long the answer to "which tools may this caller see" is kept, per caller and policy version. `0` turns the cache off. |

Three sections come from the YAML file only: `tenants`, `upstreams` and `agents` (see `keystone.example.yaml`).

## Credentials

An upstream that needs an API key gets it from Keystone, never from the agent and never from the
config file. The key is stored encrypted in Postgres (table `credentials`), and the credential slot
of the pipeline adds it to the call as an HTTP header at the last moment: after policy and
approval, so a refused call never has its credential decrypted, and dropped from the call context
as soon as the call ends. It does not appear in the tool list, in a result, in a rejection, in the
audit record or in a log line.

`credential_mode` on the upstream says whose credential it is:

| Mode | What Keystone sends |
|---|---|
| `none` (default) | Nothing |
| `static` | The upstream's own credential, the same for every caller |
| `per_user` | The credential of the user making the call. A user without one is refused with `KS_DENIED` ("no credential for this user on mail") |

```bash
echo -n "$MAIL_KEY" | keystone cred set --upstream mail --header X-Api-Key     # the value comes from stdin
keystone cred set --upstream mail --header X-Api-Key --from-env MAIL_API_KEY   # or from a variable
keystone cred set --upstream crm --user alice --header X-Api-Key --from-env ALICE_CRM_KEY
keystone cred list                                                             # who, which key, when
```

There is no option that takes the value on the command line, where a process list would show it.
On a terminal the command asks for the value without echoing it. `cred set` replaces the
credential it finds for that upstream and user, and holds one header. `cred list` prints the
tenant, upstream, user, the id of the master key and two times. It does not decrypt anything.

The vault needs `KEYSTONE_MASTER_KEYS`: one or more Fernet keys, comma separated. The first
encrypts and every one decrypts. Make a key with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. The
key in `.env.example` is public, for local use only: `KEYSTONE_ENV=prod` refuses it.

To rotate the master key, put the new key first and keep the old one, run
`keystone cred rotate-keys`, then remove the old key:

```bash
KEYSTONE_MASTER_KEYS="$NEW,$OLD" keystone cred rotate-keys     # rotated 12, already under the first key 0
KEYSTONE_MASTER_KEYS="$NEW"      keystone serve                # now the old key can go
```

It exits 1 and names the rows it could not decrypt if some credential was written under a key that
is no longer listed. A rotation never undoes a `cred set` made while it runs.

### From the environment at startup

In the config, an HTTP upstream can name the environment variable that holds its key instead of
holding it. Keystone reads the variable when it starts and stores the value in the vault through
the same code as `cred set`, before the first sync needs it:

```yaml
upstreams:
  - id: mail
    tenant: acme
    url: http://mail-mcp:8101/mcp
    credential_mode: static
    credential_env: {X-Api-Key: MAIL_API_KEY}
```

A value that has not changed is not written again. A variable that is not set leaves the stored
credential as it is, so a restart without the variable does not lose it. A name that starts with
`KEYSTONE_` is refused, so the master key cannot be used as an upstream credential by mistake.
`credential_env` on an upstream whose `credential_mode` is `none` is an error, because it would
never be sent. Keystone does not start if an upstream in the config uses credentials and
`KEYSTONE_MASTER_KEYS` is not set.

Keystone also uses an upstream's static credential for what it does on its own account: reading
the tool list (startup, the timer and `keystone registry sync`) and the health probes. A `per_user`
upstream that has a static credential is read with that one; a user's credential is never used
for it. Without a static credential those requests carry no key, so a `per_user` upstream that
demands a key even to list its tools needs a static credential as well, or its probes fail and
Keystone marks it down.

A call whose upstream gets no credential (a `static` upstream whose credential was deleted, say)
reaches the upstream without one. If the upstream answers 401 or 403, the agent gets
`KS_UPSTREAM_ERROR` ("the upstream server refused the credentials Keystone sent") at once: a
connection attempt that meets either status is not retried, because the same credential gets the
same answer, and the tests hold the call under 1 s. The log line `upstream_credentials_refused`
names the upstream. A connection that fails for any other reason still goes through the reconnect
backoff (0.2, 0.8 and 3.2 s).

An upstream that copies the key it received into a tool result does not hand it to the agent. Before
a result leaves dispatch, every credential value Keystone sent for the call, whatever its length,
and every secret registered with the log scrubber are replaced with `[redacted]`, in all text of
the result and in its structured content. The log line `upstream_result_redacted` names the
upstream and the tool, so an operator can see which server does it. Only a value that comes back as
it was sent is caught: an upstream that reverses, splits or encodes the key first is not, and a
server you do not trust belongs behind the sandbox of Phase 8.

Header names are letters, digits and dashes. `Host`, `Content-Type`, `Mcp-Session-Id` and the
other headers the HTTP layer owns are refused. Values are printable ASCII on one line, up to 4096
characters.

Every credential the vault decrypts is also registered with the log scrubber, which replaces it
wherever it appears in a log line, in a field of any name and inside an exception message. A
value shorter than 8 characters is not registered, because it would match inside ordinary words, so
use keys longer than that.

## Tenants

A tenant is one team that shares the Keystone: its upstreams, its tools, its users and its
sessions. Compose runs two, `acme` and `globex`. A token's `tenant` claim decides which one a
caller belongs to, and nothing else can: not a header, not a field of the request. A token for a
tenant that is not under `tenants` in the config gets 403 `unknown_tenant`.

| | acme | globex |
|---|---|---|
| Users | alice, olivia, lena, root | bob |
| Upstreams | mail, files, bank, echo, echostd (15 tools) | files_globex (3 tools) |

An upstream id is unique across tenants, so globex's drive is `files_globex` (its tools are
`files_globex__read_file` and so on) and not a second `files`.

A caller lists and calls only its own tenant's tools. A call to another tenant's tool, by its exact
name, gets `KS_TOOL_NOT_FOUND`, the same answer as for a name that does not exist anywhere, so
the answer does not confirm that the tool exists. `KS_DENIED` would. The gateway also drops any
tool the registry returns for another tenant, so a bug in a lookup cannot show one (invariant
I5, `tests/invariants/test_i5_tenants.py`).

Try it with `scripts/smoke/phase_3.sh`, or by hand:

```bash
KEYSTONE_TOKEN=$(scripts/get_token.sh bob support-agent) \
  uv run python scripts/smoke/mcp_probe.py call bank__get_balance '{"account": "CHK-001"}'
# error=true code=KS_TOOL_NOT_FOUND
```

## Policies

The rules that decide a call are Cedar policies kept in files, read when Keystone starts, checked
before they are used, and identified by a version. Everything is under one directory (`policy.root`):

| Path | What it holds |
|---|---|
| `schema.cedarschema` | The schema, the one source for entities and context (plan section 3.8) |
| `default/access/*.cedar`, `default/approval/*.cedar` | Rules for every tenant |
| `<tenant>/access/*.cedar`, `<tenant>/approval/*.cedar` | Rules for one tenant, named by its id |
| `demo/access/*.cedar`, `demo/approval/*.cedar` | Rules for the demo upstreams, read when `policy.include_demo` is on |

A tenant's access set is `default/` plus `demo/` (if on) plus its own directory, and so is its
approval set. The access set is standard Cedar: a call is denied unless a permit matches and no
forbid does. The approval set holds permits only, and is asked after access allowed: a permit that
matches means a person has to approve the call.

### How a call is decided

The policy slot runs after the pinning check and before approval and credentials, so a refused
call never has its credential opened. It reads the arguments a tool's `extract` config names,
builds the entities (the user as `Keystone::User::"<tenant>:<user>"` with its groups as parents,
the tool with its upstream, risk, risk level and tags) and the context (agent, trust, session
flags, taint, call count, hour in UTC and the extracted `args`), and asks the engine:

| The engine says | The agent gets | The audit record has |
|---|---|---|
| allow | the call goes on | `allow`, with the ids of the permits that allowed it |
| deny | `KS_DENIED`, "denied by policy: `<ids>`", and the ids in `_meta` as `keystone/reasons` | `deny`, with the ids of the forbids that matched, or `default-deny` when nothing allowed it |
| require approval | until Phase 6 the approval stub refuses it: `KS_DENIED`, "approval not available" | `require_approval`, with the ids of the approval permits that matched |
| the rules could not be evaluated | `KS_DENIED` with the reason `policy-error` | `deny`, reason `policy-error` |

The last row is the fail-closed rule. It covers a policy that failed to evaluate in either pass
(Cedar skips such a policy, so a broken `forbid` would otherwise not forbid), a context the schema
refuses (an `args` key it does not know), a tenant with no set, and any exception. The cause goes
to the log as `policy_evaluation_failed`, naming the policy by its id, and never to the agent. A
set with no rule that allows anything denies every call with `default-deny` (invariant I6).

`GET /_dev/audit` shows each recent call's `effect` and `reasons`, so the decision can be read
without a database.

### The tool list

`tools/list` shows a caller only the tools whose `list_tool` the policy allows. In the local stack
support sees 13 of acme's 15 tools and operators see all 15, because `mail__send_email` and
`bank__transfer` are high risk and only operators may use them. The list is only a convenience. Every call is decided again when it is
made, so a tool that is not listed is still refused if it is called by name. A listing that cannot
be decided shows nothing.

The answers are kept for `policy.list_cache_ttl_s` seconds (60) per caller and policy version, in
Redis under `ks:policy:listcache:{principal_hash}:{version}`, or in the process when there is no
Redis. The caller is the tenant, user, groups, agent, trust and roles. A reload changes the
version, so the next listing is decided under the new rules at once. A tool that is new, or whose
risk or tags changed, is decided again without waiting for the entry to expire. A listing does not
depend on the session, so a policy for `list_tool` cannot read the session flags. Redis being down
only means the answers are worked out again.

### What a load checks

A set with any problem is refused whole, and every problem is listed with the file it is in:

- The schema parses, and every policy validates against it. A misspelled attribute, an optional
  attribute read without `has`, a type error and an unknown entity type or action are all caught.
- Every policy has `@id("kebab-case-name")`. The id is what the audit log shows as the reason for
  a decision, so it is required, unique within a tenant's combined set (access and approval
  together), and not one of the names the engine uses itself (`default-deny`, `policy-error`).
- The approval set has no `forbid`. A policy there can ask for approval but cannot block a call,
  so a forbid would not do what its author expects.
- Policy templates (`?principal`) are refused: they do nothing until linked.
- A directory or file that Cedar would never read is an error too: `aproval/` instead of
  `approval/`, `base.cdar` instead of `base.cedar`, a directory that is not `default`, `demo` or
  a configured tenant, a `.cedar` file outside `access/` and `approval/`. A rule that silently does
  not load is a rule someone believes is in force. Hidden files (`.DS_Store`, editor swap files)
  are ignored.

Starting with a set that has a problem stops Keystone, and `keystone serve` prints each problem. A
reload with one is refused and the set in force stays in force.

### Versions

The version of a set is the sha256 of its files, the schema included, taken as sorted
`(relative path, content)` pairs. It does not depend on timestamps or on the order the files were
written, so the same files give the same version on every start. Each version that is loaded is
recorded in `policy_versions` with every file's path, sha256 and content, so the rules in force at
the time of a decision can be read back from the version the audit record names.

### Reloading

| How | What it does |
|---|---|
| `keystone policy reload` | Calls the endpoint below. `--url` (or `KEYSTONE_ADMIN_URL`, default `http://localhost:8080`) is the running Keystone, and `--token` (or `KEYSTONE_ADMIN_TOKEN`) is an access token of a user with the `admin` role. Exits 1 and prints every problem when the set is refused. |
| `POST /admin/api/v1/policies/reload` | Needs the `admin` role. 200: `{"version", "previous", "changed"}`. 422: `{"error": "invalid_policies", "errors": [...], "version": <the version still in force>}`. 401, 403 and 503 are as for `/mcp`. |
| `kill -HUP <pid>` | The same reload in the process that gets the signal. A refused set is logged as `policy_sighup_refused` and nothing changes. |

```bash
export KEYSTONE_ADMIN_TOKEN=$(scripts/get_token.sh root keystone-cli)
uv run keystone policy reload
# policies reloaded: version 4f0c8a1d92b3 (unchanged)
```

The admin API checks the token with the code that checks it for `/mcp`, but the caller does not
have to be a listed agent: `keystone-cli` is how the CLI signs in, and it is not under `agents`.
What lets a caller in is the `admin` role (user `root` in the local realm). A reload runs one at a
time. It records the new version before it puts the set in force, so a set that could not be
recorded is not used.

## Upstreams

Each upstream has an `id` (lowercase letters, digits and single underscores, not ending in an
underscore), a `tenant` that is listed under `tenants` and, for `transport: http`, a `url`. A
`credential_mode` (`none`, `static` or `per_user`) and per-tool settings are optional. An unknown
key is an error, so a typo does not pass quietly.

Keystone applies the `upstreams` section every time it starts. It adds or updates each entry with
`source=config`, and a config upstream that is no longer in the file is set to `disabled`. Rows are
never deleted, because audit records name upstreams. If any entry cannot be used (an unknown
tenant, a missing url, a URL the SSRF guard refuses), Keystone stops at startup, names every
problem, and writes nothing.

The URL check resolves the host and refuses it unless every address is public. It runs when an
upstream is registered, so it does not stop a name that points somewhere public today and
somewhere private later (DNS rebinding). Keep the network policy around the gateway tight in
production.

The `keystone` command manages upstreams without a restart. It reads the same settings as the
server, so run it where `KEYSTONE_DATABASE_URL` points at the right database (inside compose:
`docker compose -f deploy/docker-compose.yml exec keystone keystone upstream list`).

| Command | What it does |
|---|---|
| `keystone upstream list [--all] [--json]` | Id, tenant, transport, status, source, last sync and target. `--all` includes disabled upstreams. |
| `keystone upstream add ID --url URL [--tenant T]` | Register an http upstream with `source=cli`. The URL goes through the SSRF guard. |
| `keystone upstream add ID --transport stdio -- CMD ARGS...` | Register a stdio upstream. |
| `keystone upstream remove ID` | Disable a CLI upstream. A config upstream is removed by editing the file. |
| `keystone cred set --upstream ID --header NAME [--user U] [--from-env VAR]` | Store an upstream credential, read from stdin or the variable. |
| `keystone cred list [--json]` | Stored credentials, without their values. |
| `keystone cred rotate-keys` | Re-encrypt every credential under the first master key. |
| `keystone agent list [--json]` | The agents in the config with their trust level, and what an unlisted agent gets. |
| `keystone db upgrade` | Apply database migrations. `keystone serve --migrate` does it before starting; the compose stack uses that. |

### stdio upstreams

An upstream with `transport: stdio` is a program that Keystone starts and talks to over its
standard input and output. In the YAML it has a `command` (a list) and an optional `env` (a map);
with the CLI, put the command after `--`:
`keystone upstream add tools --transport stdio -- python -m my_server`. The compose stack starts
one, `echostd`, which runs `python -m examples.upstreams.echo_server --transport stdio` inside the
Keystone container (the image keeps `examples/` in `/app`).

The program starts when the first call or sync needs it, starts again after a crash (with the
reconnect backoff of 0.2, 0.8 and 3.2 seconds), and ends when Keystone shuts down. A call that
was running when it died fails and is not sent again. Its environment is `PATH` (Keystone's, unless
`env` sets one) and the variables in `env`, and nothing else: not `HOME`, not any `KEYSTONE_*`
variable, never the master key or the database URL. A key in `env` that starts with `KEYSTONE_` is
refused when the config loads. `env` values are plain text in the YAML, so they are for settings
and not for secrets. `env` can only be set in the YAML; an upstream added with the CLI gets just
`PATH`. POSIX only.

A stdio upstream runs as the Keystone user, with no sandbox. Whoever can write a `command` into the
`upstreams` table or run `keystone upstream add` can run a program inside the Keystone container,
so treat both as operator rights and keep the database closed. Phase 8 adds containerized stdio
upstreams for servers you do not trust.

### Tool lists and syncing

Keystone reads each upstream's tool list when it starts, every `registry.sync_interval_s`, and
when you run `keystone registry sync`. Each tool is stored with the SHA-256 of its description and
of its input schema. The `tools` block of an upstream in the YAML sets risk, tags, cost, timeout
and extractors by the upstream's own tool name (for example `send_email`, not `mail__send_email`).
A tool without an entry has risk `medium`, no tags and no cost.

An extractor reduces a call's arguments to a fact a policy may read, such as the amount of a
transfer or the domain of a recipient. The `extract` map of a tool pairs a field of the schema's
`args` record with a path and pipes:

```yaml
tools:
  send_email: {risk: high, tags: [external_effect], extract: {recipient_domain: "$.to | domain"}}
  transfer:   {risk: high, tags: [external_effect], extract: {amount: "$.amount | cents"}}
```

The path is `$.a`, `$.a.b` or `$.a[0]`, in any mix. The pipes are `int` (cut the fraction), `cents`
(times 100, rounded half up), `domain` (the domain of one plain email address, in lower case),
`lower` and `len` (of a text or a list). The key must be a field of `args` in
`policies/schema.cedarschema` (`amount`, `recipient_domain`, `path` or `count`), and the pipes
must give the type the schema says. Keystone stops at startup, naming the upstream, the tool and
the key, if one is not. An argument that is not there, or that a pipe cannot use, leaves the key
out for that call and logs why at debug level, without the value. A policy has to ask
`context.args has amount` before it reads the field.

Two cases are treated so that a rule is not skipped by accident. A number beyond the range of a
Cedar `Long` (about 9.2 x 10^18) is capped at the range, so a rule that says "over 500" still sees a
transfer of 10^30. And `domain` accepts one plain address: `a@evil.test,b@acme.test`, a display
name or a comment has no domain. With `int`, an amount of 500.99 becomes 500; use `cents` for
money and write the limit in cents.

| Command | What it does |
|---|---|
| `keystone registry sync [--upstream ID] [--json]` | Sync now and print, per upstream, how many tools were created, unchanged, changed and removed, plus the names and any errors. Exits 1 if an upstream could not be synced. |
| `keystone upstream sync ID` | The same for one upstream. |

What a sync does to a tool:

| Upstream lists the tool | Result |
|---|---|
| for the first time | created, status `active` |
| with the definition we hold | unchanged; the config's overrides are applied again |
| with a different description or schema | reported as `changed`; pinning (KS-205) decides what happens |
| no longer, in a complete list | an `active` tool becomes `disabled`, reason `removed_from_upstream`, and returns to `active` if the upstream lists it again with the same definition. A quarantined tool stays quarantined, so vanishing and coming back is no way around a review. |

A sync that fails, because the upstream is down, slow or sent a broken answer, writes the error to
the upstream's `last_error` and changes no tool. Only a complete list can show that a tool is
gone. A failure on one upstream does not touch any other upstream, and startup carries on: the
upstream's tools stay as they were and the timer tries it again at the next round. `keystone
upstream list` shows the error under the row.

### Pinning and quarantine

A tool's description is text the model reads, so a server that changes it after you approved it
can give the agent new instructions. Keystone stores the description and the schema it first saw
(the pinned definition) with their hashes, and shows agents only that.

When a sync finds a different description or schema, the tool is `quarantined`, with the reason
`description_changed`, `schema_changed` or both, and the new definition waits next to the pinned
one. A quarantined tool is left out of `tools/list`, and a call to it returns `KS_QUARANTINED`
without reaching the upstream. The check reads the tool's status from Postgres on every call, so a
quarantine made by the CLI in another process stops the very next call. If an upstream takes the
change back, the tool is released by the next sync. A newer offer replaces an older pending one.

| Command | What it does |
|---|---|
| `keystone tool list [--status S] [--json]` | Every tool with its status and reason. |
| `keystone tool show NAME` | The pinned definition, the pending one, a diff, and a fingerprint of the pending definition. |
| `keystone tool approve-change NAME [--expect FP] [--note TEXT]` | Make the pending definition the pinned one, recompute the hashes and set the tool `active`. With `--expect`, refuses if the pending definition is no longer the one with that fingerprint. The note goes in the log. |
| `keystone tool disable NAME` / `enable NAME` | Take a tool out of service by hand. Sync never re-enables a tool you disabled. `disable` and `enable` both refuse a quarantined tool (review it and approve it instead), and `enable` refuses one the upstream stopped listing. |

A tool seen for the first time is screened too (`keystone.defense.description_check`). Five
rules look for characters a reader cannot see (tag characters, zero-width and bidirectional
controls), phrases such as "ignore all previous instructions" or "do not tell the user", the pseudo
tags `<important>` and `<system>`, "before using this tool" together with read, send or call, and a
description longer than 2,000 characters. A tool that trips any of them is created `quarantined`
with the reason `suspicious_description:<rule ids>`, and has no pending definition. The agent is
told the category only, not which rule fired. `approve-change` releases it as it is after you have
read it. This is a short list of crude patterns and a determined author will get past it. It is
meant to stop the careless cases and to make a person look; Phase 7 replaces it with a scanner.
Try it: `ECHO_POISONED=1` makes the demo echo server list a tool that is held at first sight.

Review with `tool show`, then approve with the fingerprint it printed:
`keystone tool approve-change echo__echo --expect 1a2b3c4d5e6f`. Without `--expect`, a server
that changes the definition again between your review and your approval gets the second version
approved. The approval is logged now; the audit log records it from Phase 5.

### Health

Every `health.interval_s` Keystone asks each live upstream for its first page of tools, with a
`health.timeout_s` limit. A failed probe makes the upstream `degraded`, and `health.down_after`
failed probes in a row make it `down`. One good probe makes it `up` again. The probes go on while
an upstream is down, which is how it comes back. With the defaults an upstream that stops
answering is `down` after about 90 seconds.

A call to a `down` upstream is refused at once with `KS_UPSTREAM_ERROR` ("upstream bank is down")
and is not sent. Its audit record shows `dispatched: false`. The tools of a `down` upstream stay
in the list, because the upstream may be back before the next `tools/list`.

`GET /readyz` has an `upstreams` object next to `dependencies`:
`{"upstreams": {"bank": "down", "mail": "up"}}`. An upstream that is down does not change the HTTP
status. Only Postgres and Redis do.

### Telling clients about changes

When a sync changes which tools a tenant can see (a tool appears, disappears or changes
definition), Keystone sends `notifications/tools/list_changed` to that tenant's open sessions. A
change made by the CLI in another process is noticed within `registry.cache_ttl_s`. Only a client
that keeps the standalone GET stream open receives it; others see the change at their next
`tools/list`.

Without `--tenant`, `add` uses the config's only tenant, and fails when the config names none or
several.

## Sessions

Each MCP session has a state object (flags, taint, call count, spend) stored as JSON in Redis
under `ks:sess:{session id}`. The key lives 24 hours from its last use: both reading and writing
a session restart the clock. Postgres holds one `sessions` row per session, written when the
session opens, as the durable reference that audit records will point at. The row's
`last_seen_at`, flags and taint are updated at most once a minute per session.

If Redis cannot be reached, a call is refused with `KS_DENIED` ("session state is unavailable") and
audited, because a call must not run without the flags and taint of its session. If Postgres
cannot write the row, the call goes ahead and the failure is logged. A request that names no MCP
session id gets a throwaway state that is never stored. Redis database 15 belongs to the tests;
they empty it.

A session is bound to the principal that opened it. When `initialize` creates the session,
Keystone records the tenant, the user and the agent of the token next to the new session id,
before the client learns the id. Every later request that names the session must carry a token
with the same three values, or it gets 403 `session belongs to another principal`. A different
token for the same principal (a refreshed one, with changed groups) is fine, and each call is
decided on the groups of its own token. A session id Keystone has no binding for gets 404, which
makes a client start a new session; it is never adopted by whoever names it first. The binding
is kept in the gateway process, like the SDK's own sessions, so it does not depend on Redis
being up.

## The MCP endpoint

`POST /mcp` on port 8080 speaks MCP over streamable HTTP. Keystone serves the handshake protocol
era only (ADR-0003). A client in its default `auto` mode falls back to it by itself. A client
pinned to the `2026-07-28` version is refused.

Every request needs `Authorization: Bearer <token>`. The Host header is checked first (421 for an
address that is not in `KEYSTONE_ALLOWED_HOSTS`), then the token:

| Answer | When |
|---|---|
| 401 with `WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource"` | No token, or a token that is invalid. The body says why: `{"error": "invalid_token", "reason": "expired"}` |
| 403 | The token is sound but its agent is not under `agents` (`unknown_agent`), or it names a session that another principal opened |
| 404 | The request names a session that no one opened here |
| 503 with `Retry-After` | The identity provider's keys cannot be fetched |

`GET /.well-known/oauth-protected-resource` (RFC 9728) returns
`{"resource": "<base>/mcp", "authorization_servers": ["<issuer>"], "bearer_methods_supported":
["header"]}`, so an MCP client that supports OAuth can find the identity provider from the 401
without it being written into the client. `/healthz`, `/readyz` and that document need no token.

With `KEYSTONE_AUTH__MODE=none` (dev and test only) there is no check, and every caller is the dev
principal. Keep that on localhost.

`GET /_dev/audit` returns how many calls the in-memory audit log holds and the last 50, each with
its tool, outcome, the policy's decision (`effect`) and the `reasons`. It exists for the demo and
the smoke scripts, is not mounted when `KEYSTONE_ENV=prod`, and goes away when the admin API
arrives in Phase 5.

Every result carries `keystone/call_id` in its `_meta`. A call that Keystone refuses (unknown
tool, invalid arguments) comes back as a normal result with
`isError` set. Its text starts with `[keystone:<CODE>] call <id>`, and the machine-readable copy
(`keystone/code`, `keystone/call_id`) is in the `_meta` of the result and of the first content
block (ADR-0007).

Health endpoints: `GET /healthz` always returns 200. `GET /readyz` probes Postgres and Redis with
a 1 second limit each and returns 503 if either is down.

## Troubleshooting

| Symptom | Check |
|---|---|
| `make demo` says it cannot reset an upstream | The stack is down. Run `make up`. |
| An agent gets `Unsupported protocol version` | It pinned the `2026-07-28` version. Use the default mode or `mode="legacy"`. |
| `421 Invalid Host header` from `/mcp` | The `Host` is not in `KEYSTONE_ALLOWED_HOSTS`. Add it, for example `keystone:*`. |
| `make up` times out on Keycloak | `docker compose -f deploy/docker-compose.yml logs keycloak`. First start imports the realm and can take 60 seconds on a slow disk. |
| `get_token.sh` says `Invalid user credentials` | The realm was imported with other passwords (an older `.env`, or `.env` changed after the first start). Recreate Keycloak, see "Changing the realm". |
| `401` with `reason: expired` | The token is older than five minutes. Get a new one with `scripts/get_token.sh`. |
| `401` with `reason: wrong_issuer` | The token was issued under another address than `KEYSTONE_OIDC_ISSUER`. Get tokens from `http://localhost:8180`, the address in the setting. |
| `403` with `reason: unknown_agent` | The token's `azp` is not under `agents`. Add it, or run `keystone agent list`. |
| `503` from `/mcp` | Keystone cannot read the identity provider's keys. Check `KEYSTONE_OIDC_DISCOVERY_URL` and that Keycloak is up; the log says `jwks_fetch_failed` or `oidc_issuer_mismatch`. |
| Port already in use | Another process holds the port. Set a different one in `.env`. |
| `make check` cannot reach Postgres | Run `make up-core`, then `docker compose -f deploy/docker-compose.yml ps`. |
| `ModuleNotFoundError: keystone` right after `uv sync` (macOS) | A background process flagged `.venv` as hidden, and Python skips hidden `.pth` files. Check with `ls -lO .venv/lib/python3.12/site-packages/keystone.pth`. Set `UV_PROJECT_ENVIRONMENT` to a path outside the repo, for example `$HOME/.cache/keystone-venv`, then run `uv sync`. |
