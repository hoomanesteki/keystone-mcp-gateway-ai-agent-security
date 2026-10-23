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
| `bash scripts/smoke/phase_1.sh` | The body of `make demo`; exits 1 if a step fails or the audit log (read through the admin API) does not hold one new record for each call |
| `bash scripts/smoke/phase_6.sh` | Three agents run as olivia and lena decides through the admin API: a transfer of 900 is held, approved and completed (a second decision is 409 and olivia's own is 403); one of 700 is rejected with a note that the agent gets; one of 600 times out as `KS_APPROVAL_PENDING`, is approved late and is awaited. Then the audit log and `keystone_approvals_pending` are checked. About 20 seconds: the third request waits out the 10 s hold. |
| `bash scripts/smoke/phase_5.sh` | Runs the demo, finds a Jaeger trace of more than 9 spans with no user or argument in it, reads `keystone_tool_calls_total` from `/metrics` and from Prometheus, finds the dashboard in Grafana, verifies the audit chain, edits a record as the Postgres superuser and checks that `keystone audit verify` exits 2 and names the seq, then puts the record back. About 15 seconds. |
| `bash scripts/smoke/phase_4.sh` | Alice's transfer is `KS_DENIED default-deny` and her tool list has 15 tools (13 of acme's and Keystone's 2); olivia's transfer of 900 is held for approval, lena rejects it through the admin API and olivia is told `KS_APPROVAL_REJECTED`, the audit shows `require_approval` / `approve-transfer-over-500` and one of 100 is dispatched; a policy file is broken on the host, the reload answers 422 with the version unchanged, and the file is put back. About 30 seconds. |
| `bash scripts/smoke/phase_3.sh` | Tokens for alice and bob, a request without a token (401), olivia's 17 tools, bob's 3 globex tools and Keystone's 2, and `KS_TOOL_NOT_FOUND` for an acme tool, the mail server's `api_key_received`, and a search of the Keystone logs for the demo keys and the master key. About 15 seconds. |
| `bash scripts/smoke/phase_2.sh` | Lists the 17 tools, quarantines and approves a changed echo description, stops the bank server and checks the refusal. About 45 seconds. It restarts Keystone with a 2 s health probe (`SMOKE_HEALTH_INTERVAL_S`) and restores everything when it ends. |

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
| `KEYSTONE_DATABASE_URL` | `postgresql+asyncpg://keystone:keystone@localhost:55432/keystone` | Postgres DSN. Compose runs Keystone as the role `keystone_app` (see Database roles). |
| `KEYSTONE_MIGRATE_DATABASE_URL` | unset | Where `keystone db upgrade` and `keystone serve --migrate` connect, when that is not `KEYSTONE_DATABASE_URL`: creating tables takes the role that owns them. Unset means they use `KEYSTONE_DATABASE_URL`. Compose sets it to the owner. |
| `KEYSTONE_APP_DB_PASSWORD` | the development password | Read by the migration that creates the `keystone_app` role. With `KEYSTONE_ENV=prod` and no value, that migration stops. It is not a Keystone setting: set the same value in the password of `KEYSTONE_DATABASE_URL`. |
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
| `KEYSTONE_CONSOLE_ORIGIN` | `http://localhost:5173` | The one origin a browser may call the admin API from (CORS). A preflight from any other origin is refused with 400. Write it as `scheme://host[:port]`. |
| `KEYSTONE_OTLP_ENDPOINT` | unset | Where spans are sent: an OTLP/HTTP endpoint such as `http://jaeger:4318` (`/v1/traces` is added). Unset means no spans are made and audit rows carry no `trace_id`. Compose sets it to Jaeger. |
| `KEYSTONE_AUDIT__FAIL_CLOSED` | `true`, except `false` when `KEYSTONE_ENV=dev` | While the audit writer is unhealthy (its queue is over 90% full, or a flush failed less than 5 seconds ago), refuse every call with `KS_DENIED` and the reason `audit-unavailable`, before any interceptor runs. See Audit. Also `audit.fail_closed` in the YAML. |
| `KEYSTONE_AUDIT__REDACT_KEYS` | `[]` | JSON list of argument keys whose values the audit log replaces with `[redacted]`, besides keys that look like secrets. Whole names, any case: `["ssn", "dob"]`. Also `audit.redact_keys` in the YAML. |
| `KEYSTONE_POLICY__ROOT` | `policies` | The directory with the schema and the policies (see Policies). A relative path is read from the working directory; the image has its own copy at `/app/policies`, and compose mounts this checkout's at `/etc/keystone/policies`. Also `policy.root` in the YAML. |
| `KEYSTONE_POLICY__INCLUDE_DEMO` | `false` | Also read `demo/`, the rules that go with the demo upstreams. Compose turns it on. |
| `KEYSTONE_POLICY__LIST_CACHE_TTL_S` | `60` | How long the answer to "which tools may this caller see" is kept, per caller and policy version. `0` turns the cache off. |
| `KEYSTONE_APPROVALS__WAIT_SECONDS` | `60` | How long a call that needs approval is held before the agent gets `KS_APPROVAL_PENDING` and an id. `0` never holds one; at most 300. See Approvals. |
| `KEYSTONE_APPROVALS__TTL_SECONDS` | `900` | How long after the request it can be decided and used. |
| `KEYSTONE_APPROVALS__SWEEP_INTERVAL_S` | `30` | Seconds between marking requests that ran out of time as expired. |
| `KEYSTONE_APPROVALS__POLL_INTERVAL_S` | `2` | Seconds between looks at a request a call is waiting for, when Redis has not woken it. |
| `KEYSTONE_APPROVALS__WEBHOOK_URL` | unset | Where a new request is announced, signed (see Approvals). Needs `KEYSTONE_APPROVALS_WEBHOOK_SECRET`. |
| `KEYSTONE_APPROVALS_WEBHOOK_SECRET` | unset | The key that signs the webhook, at least 16 characters. Read from the environment only, never from the YAML. Not a nested setting: one underscore. |
| `KEYSTONE_APPROVALS__SLACK_WEBHOOK_URL` | unset | A Slack incoming webhook that gets a plain message for each request. A secret. |
| `KEYSTONE_APPROVALS__WEBHOOK_BACKOFF_S` | `[1, 2, 4]` | JSON list of the seconds before each retry of a webhook delivery. |

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
before they are used, and identified by a version. `docs/policies.md` explains how to write them,
with examples and the usual mistakes. Everything is under one directory (`policy.root`):

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
| require approval | the call is held for a person (see Approvals), then runs, or ends as `KS_APPROVAL_REJECTED`, `KS_APPROVAL_EXPIRED` or `KS_APPROVAL_PENDING` | `require_approval`, with the ids of the approval permits that matched |
| the rules could not be evaluated | `KS_DENIED` with the reason `policy-error` | `deny`, reason `policy-error` |

The last row is the fail-closed rule. It covers a policy that failed to evaluate in either pass
(Cedar skips such a policy, so a broken `forbid` would otherwise not forbid), a context the schema
refuses (an `args` key it does not know), a tenant with no set, and any exception. The cause goes
to the log as `policy_evaluation_failed`, naming the policy by its id, and never to the agent. A
set with no rule that allows anything denies every call with `default-deny` (invariant I6).

Each call's audit record holds the `effect`, the `decision_source` and the `reasons`, so the
decision can be read back from the log (see Audit).

### The default pack

| File | Policy | What it does |
|---|---|---|
| `default/access/base.cedar` | `same-tenant-low-medium` | Anyone may list and call low and medium risk tools of their own tenant |
| | `operators-high` | Members of `operators` may also use high risk tools of their tenant |
| | `admins-critical` | Members of `admins` may use critical tools of their tenant |
| | `deny-cross-tenant` | No one uses another tenant's tool, whatever else allows it |
| `demo/approval/bank.cedar` | `approve-transfer-over-500` | A transfer over 500, or one whose amount could not be read, needs approval |
| `acme/approval/mail.cedar` | `external-email-needs-approval` | A message to anyone outside `acme.test`, or to a recipient that is not one plain address, needs approval |

Risk comes from the upstream config, so in the local stack `mail__send_email` and
`bank__transfer` are high risk: support (alice) is refused both with `default-deny`, and an
operator (olivia) is allowed `bank__transfer` up to 500 and `mail__send_email` to `acme.test`
(`operators-high`), and asked about the rest: the call waits for a person (see Approvals), and
nothing is sent or moved until one approves it. `scripts/smoke/phase_4.sh` runs the demo.

### The tool list

`tools/list` shows a caller only the tools whose `list_tool` the policy allows. In the local stack
support sees 13 of acme's 15 tools and operators see all 15, because `mail__send_email` and
`bank__transfer` are high risk and only operators may use them. Every caller is also offered the
two tools that Keystone serves itself (see Approvals), which the policy does not decide. The list
is only a convenience. Every call is decided again when it is
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
  are ignored. With no tenant configured nothing can be served, so tenant directories are not
  read and not checked.

Starting with a set that has a problem stops Keystone, and `keystone serve` prints each problem. A
reload with one is refused and the set in force stays in force.

### Versions

The version of a set is the sha256 of its files, the schema included, taken as sorted
`(relative path, content)` pairs. It does not depend on timestamps or on the order the files were
written, so the same files give the same version on every start. Each version that is loaded is
recorded in `policy_versions` with every file's path, sha256 and content, so the rules in force at
the time of a decision can be read back from the version the audit record names.

### Testing

`uv run keystone policy test policies tests/policy_cases --coverage` runs the cases in
`tests/policy_cases/` through the loader and the engine, prints one row per case and exits 1 if any
case decides differently or a policy was matched by no case. The `policy` job of CI runs it on every
push, and `make gate` expects it to pass. `docs/policies.md` describes the case format.

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

## Approvals

A call that the policy sends to approval (`require_approval`) waits for a person. Each request is a
row in `approvals`, and it is specific, time-limited and used once. This section describes the
service that keeps the rows. The interceptor that holds the call, the tools an agent waits with
and the API an approver uses come after it.

A row holds the tool, the arguments with secrets masked (`args_redacted`, the same masking the
audit log uses), who asked (user, agent, session, call), the ids of the policies that asked, and
the original arguments encrypted with the vault's keys (`args_ciphertext`) so that an approved call
runs with exactly them. It also holds `args_digest`, the sha256 of the canonical JSON of the
arguments that the audit log writes as `args_digest`. The approval is for that digest: it cannot
be used for other arguments.

| State | How it gets there |
|---|---|
| `pending` | The call was sent to approval |
| `approved`, `rejected` | A person with the `approver` or `admin` role decided |
| `consumed` | The approved request was used by the call it was made for |
| `expired` | `ttl_seconds` passed before it was decided or used |

The rules, each one SQL statement in `src/keystone/approvals/service.py`:

- **Decide.** A request changes only while it is pending, unexpired, in the approver's tenant and
  not requested by the approver. The user who asked can never approve their own request, whatever
  roles they hold, and an approver of another tenant gets "not found". Two decisions at once leave
  one: the other is told the request is no longer pending.
- **Use.** An approval is used by one `UPDATE` that checks the status (`approved`), the tenant,
  the tool, the session, the user, the digest of the arguments and that it has not expired. It
  returns whether it changed a row, so of two calls that present one approval exactly one gets it.
- **Time.** `expires_at` is set from the database clock, and both statements compare it with
  `clock_timestamp()`. They do not use `now()`: that is the start of the transaction, so a
  statement held up by a row lock would be judged by a time before it waited, and could use an
  approval after it had expired. `test_a_consume_that_waited_for_a_lock_past_the_expiry_fails`
  holds a lock across an expiry to show the difference. The sweeper marks expired rows every 30
  seconds; nothing depends on it for safety.
- **Waiting.** A waiter subscribes to `ks:approval:<id>` on Redis, reads the row, and sleeps until
  a message arrives or `poll_interval_s` passes. A message only wakes it. The verdict is always
  read from the row, so a message that is lost or forged decides nothing, and without Redis the
  wait polls.
- **Keeping.** The original arguments are kept for one purpose, to run an approved call. The
  statement that makes a request unusable (a rejection, a use, the sweeper marking it expired)
  empties them in the same change. The masked form, the digest and who decided stay.
- **Ids.** An id comes from an agent's arguments or a URL, and Postgres cannot hold a NUL
  character. Ids are cleaned like every other value, so an id with one is a request nobody has.

`keystone_approvals_pending{tenant}` counts the pending requests of each tenant. It is set when
the sweeper starts and after each request, decision and sweep.

Approvals need `KEYSTONE_MASTER_KEYS`, because the arguments are encrypted with the vault's keys.
Without them there is no approval service and a call that needs approval is refused with
`KS_DENIED`, "approval not available". Rotating the keys needs no re-encryption of the arguments:
every key decrypts, and a request lives for 15 minutes at most. Removing a key before the requests
it encrypted have expired makes those requests unusable.

### Holding a call

The approval slot runs after the policy slot. For a `require_approval` decision it does one of two
things (`gateway/interceptors/approval.py`, ADR-0010).

A new call is stored as a request and held in line for `approvals.wait_seconds` (60 by default;
the local stack uses 10). The agent sees one slow call, and then one of:

| What happened in the wait | The agent gets | The audit record has |
|---|---|---|
| a person approved it | the upstream's result, as if there had been no approval | `require_approval`, outcome `ok`, `dispatched` true, and `approval:<id>` after the policy's reasons |
| a person rejected it | `KS_APPROVAL_REJECTED`, with the approver's note as the message | outcome `rejected`, code `KS_APPROVAL_REJECTED` |
| it expired | `KS_APPROVAL_EXPIRED` | outcome `rejected`, code `KS_APPROVAL_EXPIRED` |
| nobody decided | `KS_APPROVAL_PENDING` | outcome `rejected`, code `KS_APPROVAL_PENDING` |

A pending answer carries the id of the request in the text, where a model reads it, and in `_meta`
as `keystone/approval_id`, with `keystone/expires_at` and `keystone/next` (`call
keystone__await_approval`). The call does not run until the request is approved and used.

A call that is approved in the wait is checked again before its approval is used. The slots ahead
of the approval slot decided it before the wait, and a tool may have been quarantined, a policy
reloaded or a budget spent since. They run a second time (pinning, budget and policy; the rate
limit does not, since a call is charged once) and what they say stands: a quarantined tool ends the
call with `KS_QUARANTINED`, a policy that now denies it with `KS_DENIED`, an unhealthy audit log
with `KS_DENIED` ("audit unavailable"), and in each case the approval is left unused. If the policy
no longer asks for approval the call goes on as an allow and the approval is not used. The agent
is not handed the id of an approval that was left unused: it asks again, and a person decides
again. The record of a call that ran on an approval ends its reasons with `approval:<id>`, so the
audit log says which approval allowed it and the approval row says who decided.

A call that arrives with an approval id on its context is the re-entry of a call that waited. The
slot takes the id off the context, uses the approval against the call's tool, session, user and
arguments digest, and puts the id back only if that worked. The pipeline dispatches a
`require_approval` call only when the id is on the context (KS-191), so a call with a made-up id,
one for other arguments, a used one or an expired one is refused with `KS_APPROVAL_EXPIRED` and
never reaches the upstream. Invariant I7 (`tests/invariants/test_i7_approvals.py`) tries every
combination of an id in each of its six states with arguments, tool, session and user that are the
approved ones or not: exactly one dispatches.

### Deciding through the API

The console and scripts decide with three routes. A caller needs the `approver` or the `admin`
role, and sees the requests of the tenant of the token only.

`GET /approvals?status=pending` answers a list, oldest first. `GET /approvals/{id}` answers one
request and `recent_calls`. Each request has: `id`, `status`, `tool`, `risk` and `tags` (of the
tool, `null` if the tool is not registered), `arguments` (secrets masked), `args_digest`,
`reasons` (the ids of the policies that asked), `requested_by_user`, `requested_by_agent`,
`arguments_masked`, `own_request` (true when the caller made it and so cannot decide it),
`session_id`, `call_id`, `requested_at`, `expires_at`, `expires_in_s` (counted by the server, so a
clock that is wrong in the browser does not matter), `decided_by`, `decision_note`, `decided_at`,
and `flags` and `tainted` of the session that asked. The session is read without keeping it alive.

The `arguments` are what the audit log keeps of them: the value under a key that looks like a
secret is `[redacted]`, a card number, a social security number, a bearer token, an AWS key id or a
private key inside a string is replaced, a string over 2,048 characters is cut to its first 256
characters and the sha256 of the whole, and arguments that are still over 16 KiB after that are
replaced by a note. `arguments_masked` is true when any of that happened. What runs is more than
what is shown, so an approver should treat what is not shown as unknown, and a console should say
so next to the decision. It does not block a decision. `args_digest` is the digest of the real
arguments, and the approval is for exactly those.

`POST /approvals/{id}/decision` takes `{"approve": true|false, "note": "..."}` (the note is
optional and at most 500 characters; `approve` must be a JSON boolean and an unknown key is an
error) and answers the request as it now stands.

| Status | When |
|---|---|
| 200 | The decision was made |
| 401 | No token, or one that is not valid |
| 403 | No approver or admin role, or the request is the caller's own |
| 404 | There is no such request in the caller's tenant (another tenant's looks the same, and so does an id that is not one) |
| 409 | The request is no longer pending. The body is `{"error": "conflict", "reason": "the request is approved", "status": "approved"}`; `status` is `approved`, `rejected`, `consumed` or `expired`. A request past its time is `expired` at once, before the sweeper has marked it |
| 422 | The body is not a decision |
| 503 | Keystone has no master keys, so there are no approvals |

The decision is one statement (see above), so two approvers who decide together get one 200 and
one 409. A rejection reaches the agent as `KS_APPROVAL_REJECTED` with the note.

### Telling others

`approvals.webhook_url` (`KEYSTONE_APPROVALS__WEBHOOK_URL`) makes Keystone `POST` a JSON body to
that address when a request is made:

```json
{"id": "01J...", "tenant": "acme", "tool": "bank__transfer", "requester": "olivia",
 "agent": "ops-agent", "reasons": ["approve-transfer-over-500"],
 "expires_at": "2026-10-23T12:15:00+00:00",
 "console_url": "http://localhost:5173/approvals?id=01J..."}
```

The arguments are not in it. The body is signed, so the receiver can check where it came from and
how old it is:

```
X-Keystone-Timestamp: 1761218100
X-Keystone-Signature: sha256=<hex HMAC-SHA256 of timestamp + "." + body>
```

The key is `KEYSTONE_APPROVALS_WEBHOOK_SECRET`. It is read from the environment and from nowhere else:
a `webhook_secret` in the YAML is an error, and Keystone does not start with a webhook and no
secret, or with one shorter than 16 characters (`openssl rand -hex 32` makes a good one). A receiver
checks it like this, and refuses a timestamp older than a few minutes:

```python
import hashlib, hmac


def valid(secret: bytes, timestamp: str, signature: str, body: bytes) -> bool:
    mac = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, f"sha256={mac}")
```

A delivery never delays the call that asked. It is queued and sent by a task of its own, with 5
seconds for each attempt and three retries after 1, 2 and 4 seconds (`approvals.webhook_backoff_s`
changes them). A network error, a timeout, a 408, a 429 and a 5xx are retried; any other answer
ends the delivery. Failures are logged with the receiver's host and no more. The queue holds 100
notifications and drops the rest, logging `approval_notification_dropped`.

`approvals.slack_webhook_url` (`KEYSTONE_APPROVALS__SLACK_WEBHOOK_URL`) sends a plain message to a
Slack incoming webhook: who wants to call which tool, the reasons and the console link. Its address
is a secret, so it is held as one and never logged; set it from the environment. The agent's id, the
tool's name and the reasons are written by others, so `&`, `<` and `>` in them are escaped and a
name such as `<!channel>` reads as text and pings no one.

### Keystone's own tools

Two tools belong to Keystone itself. Their names start with `keystone__`, the id of a pseudo-upstream
that no configured upstream can have: the config loader, `keystone upstream add` and the registry
all refuse the id `keystone`, and the gateway does not believe a registry row that claims it. Every
caller is offered both in `tools/list`, whatever the policy says about the rest. A call to either
goes through the pipeline like any other. The policy slot gives it `allow` with the decision source
`virtual` and the reason `virtual-tool`, and does not ask Cedar (an empty policy set still offers
and answers them: they are the exception to I6, and the await tool runs a call that the policy
decides again). The pinning and credential slots have nothing to look up for them. Rate limits, the
audit sink, tracing and metrics apply as they do to every call.

| Tool | Arguments | What it does |
|---|---|---|
| `keystone__await_approval` | `approval_id` (from `KS_APPROVAL_PENDING`), `wait_seconds` (0 to 120, 60 by default) | Waits for the request, and when it is approved runs the call that waited |
| `keystone__whoami` | none | Returns `principal` (`tenant_id`, `user_id`, `groups`, `agent_id`, `agent_trust`, `scopes`, `roles`), `flags`, `tainted`, `call_count` and `spent_usd` |

`keystone__whoami` shows who Keystone thinks the caller is and the state of the session. It never
returns a token or a credential: the principal holds none.

`keystone__await_approval` answers only for a request made by this user, through this agent, in this
session. An id that does not exist, one of another tenant, another user or another session gets the
same `KS_DENIED`, "there is no such approval request for this session". For an id that is the
caller's it waits up to `wait_seconds`, then:

| The request is | The agent gets |
|---|---|
| approved | the result of the original call, which ran just now with the arguments that were approved |
| rejected | `KS_APPROVAL_REJECTED` with the note |
| expired, or already used | `KS_APPROVAL_EXPIRED` |
| still pending | `KS_APPROVAL_PENDING` again, with the same id |

The original call runs through the whole pipeline again, as a call of its own with a new call id.
The tool must still be active (a quarantine since then refuses it), the policy decides again under
the rules in force now, and the approval is used against the tool, session, user and arguments it
was made for. A policy that has been tightened since the approval refuses the call with
`KS_DENIED`, and the approval is kept: when the rule is lifted the same id completes the call. The
audit log has a record for the call that was told to wait, one for the call the await ran, and one
for the await (source `virtual`). A client must not give up on a held call before the hold ends: an
HTTP read timeout shorter than `approvals.wait_seconds` (or than the `wait_seconds` of an await)
ends the connection, not the request. The scripted agent waits up to 330 seconds.

### What approvals do not do

- **Revoke.** An approval is good until it is used or `approvals.ttl_seconds` have passed since the
  request (15 minutes by default). To stop a call that is approved already, quarantine or disable
  the tool, or change the policy: the call is checked at the time of use and refused.
- **Spare an approval that a later slot refuses.** The approval is used before the credential slot
  and the dispatcher run. A call refused there, for a per-user credential that is missing or an
  upstream that is marked down, has spent its approval, and a person decides again.
- **Limit.** Nothing caps the requests one user or session leaves pending, merges identical ones (an
  approver who approves two lets the call run twice) or counts the callers waiting at once; every
  waiter holds a Redis connection and polls the table. The rate limits and budgets of Phase 8 are
  where that belongs. The queue API shows the oldest 200 requests.
- **Put the approvals table in the audit chain.** The table is not part of the tamper-evident
  chain, and the role Keystone connects as can change it. The audit record of a call that ran on
  an approval names it, which ties the two together without protecting the table.

## Upstreams

Each upstream has an `id` (lowercase letters, digits and single underscores, not ending in an
underscore, and not `keystone`, which is reserved for Keystone's own tools), a `tenant` that is
listed under `tenants` and, for `transport: http`, a `url`. A
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

## Audit

Every tool call leaves one row in the `audit_events` table: who (tenant, user, agent, session),
what (the tool), what was decided (`effect`, `decision_source`, `reasons`, `policy_version`),
what happened (`outcome` `ok`, `rejected` or `error`, `reject_code`, `dispatched`), what it cost,
how long it took, and the hash chain. A call that Keystone refuses before it enters the pipeline
(a tool that does not exist) has a row too. Rows are only ever added.

Each row holds the hash of the row before it, and its own hash covers that and every other column.
Changing a row changes its hash, and removing one breaks the link after it. The chain is the same
across several Keystone processes: each batch takes a Postgres advisory lock, reads the last hash
and extends it. ADR-0009 has the rules and what the chain does not prove.

The pipeline hands the row to a writer and goes on. The writer takes up to 200 rows or 50
milliseconds at a time and writes each batch in one transaction. What it does when that fails:

| What went wrong | What the writer does | What you see |
|---|---|---|
| The database is down, slow or refuses the connection | Keeps the batch and everything behind it, in order, and tries again after 0.2 s, doubling to 3 s | `audit_flush_failed` in the log, `keystone_audit_failures_total{reason="flush_failed"}` rising |
| The database refuses one record (a constraint or a type) | Halves the batch until that record is alone, drops it, writes the rest | `audit_record_dropped` with the call id, `reason="record_dropped"` |
| The queue (10,000 records) is full for 5 seconds | Refuses the new record | `audit_queue_full`, `reason="queue_full"` |
| Keystone stops | Flushes the queue, for 10 seconds at most | `audit_shutdown_dropped` and `reason="shutdown_dropped"` for whatever is left |

A process that is killed loses the rows it had not written, at most the last 50 ms of calls.

A row keeps the arguments of the call, masked, and the sha256 of the original ones. A key that
looks like a secret (`secret`, `token`, `password`, `api key`, `authorization`) or is listed in
`audit.redact_keys` has its value replaced by `[redacted]`. In strings, payment card numbers,
US social security numbers, bearer tokens, AWS access key ids and private key blocks are masked,
and a string over 2,048 characters is cut to 256 characters and its sha256. The patterns are a net
with holes; list the keys of any field you know is sensitive. To prove what a call sent, hash the
canonical JSON of the original arguments (sorted keys, no spaces) and compare it with `args_digest`.

The writer is unhealthy when its queue is over 90% full or a flush failed less than 5 seconds ago.
With `audit.fail_closed` on, which is the default outside `dev`, an unhealthy writer makes the
pipeline refuse each call before it runs an interceptor: `KS_DENIED`, "audit unavailable", with
`keystone/reason: audit-unavailable` in `_meta`, and a row for the refusal once the writer can
take it. In `dev` the call goes ahead and the failure is counted.

### Checking and exporting the log

`keystone audit verify` reads every row in `seq` order and recomputes the hashes from what Postgres
returns. It prints `OK, 42 records` and exits 0, or `broken at seq 10: hash mismatch` (a row was
edited, or its link to the row before it was) or `broken at seq 5: gap` (a row is missing) and
exits 2. `--from-seq N` starts at record N, and trusts the stored hash of record N-1 as the anchor
without checking that record, so it says nothing about the records before N.

```bash
docker compose -f deploy/docker-compose.yml exec keystone keystone audit verify
```

`keystone audit export [--since T] [--until T] [--tenant ID]` writes the records as JSON lines to
standard output, from `--since` (inclusive) up to `--until` (exclusive), as dates or times
(`2026-10-01`, `2026-10-01T12:00:00Z`; UTC unless the time says otherwise). A line holds the
columns of one record in the form its hash covers, so whoever receives the file can check it with
a sha256 and a JSON library: the hash is the sha256 of the previous hash (as bytes) followed by the
canonical JSON (sorted keys, no spaces) of the line without `seq`, `prev_hash` and `hash`. A tenant's
export has gaps in `seq`, because the chain runs through every tenant's records; each line still
proves itself.

What verify cannot see: a log that was cut short (the newest rows deleted) is still a whole chain,
and so is one whose every row and hash was rewritten. Publish the latest hash somewhere out of
reach to close both (ADR-0009).

### Database roles

Migrations run as the role that owns the tables. Keystone runs as `keystone_app`, which the
migration `0006` creates (`CREATE ROLE ... LOGIN`, with `KEYSTONE_APP_DB_PASSWORD`). It may select,
insert, update and delete in every table, and on `audit_events` it may only insert and select, so a
compromised gateway cannot edit or delete what it logged. Tables that later migrations create are
open to it by default privileges. It has no access to `alembic_version`. A role belongs to the
Postgres cluster, not to one database, so the migration leaves an existing `keystone_app` as it is:
change its password with `ALTER ROLE keystone_app PASSWORD '...'`, and change the password in
`KEYSTONE_DATABASE_URL` with it. The owner, and any Postgres superuser, can still change the log;
that is how the Phase 5 smoke shows verify catching an edit.

The rows are read through the admin API (`GET /admin/api/v1/audit`), through
`keystone audit export`, or with `psql` as the database owner:

```bash
docker compose -f deploy/docker-compose.yml exec postgres psql -U keystone -d keystone \
  -c "SELECT seq, tool_name, effect, reasons, outcome FROM audit_events ORDER BY seq DESC LIMIT 10"
```

## Tracing

With `KEYSTONE_OTLP_ENDPOINT` set (compose points it at Jaeger), every tool call is one trace, and
Jaeger shows it at http://localhost:16686 under the service `keystone`. The root span is
`keystone.tool_call` (kind server). Under it are one `keystone.interceptor.<name>` span for each
hook of each interceptor (`keystone.hook` says `before_call` or `after_call`) and
`keystone.upstream.call` (kind client, with `keystone.upstream`). The audit row of the call holds the
trace id.

The root span carries:

| Attribute | Value |
|---|---|
| `gen_ai.operation.name` | `execute_tool` |
| `gen_ai.tool.name`, `gen_ai.tool.call.id` | the tool, and the call id |
| `keystone.tenant`, `keystone.agent` | the tenant and the agent of the token |
| `keystone.user_hash` | the first 12 hex characters of the sha256 of the user id |
| `keystone.decision.effect`, `keystone.decision.reasons` | what the policy decided, once it has |
| `keystone.outcome`, `keystone.reject_code` | `ok`, `rejected` or `error`, and the code that refused the call |

No span holds a raw user id or an argument value, and no exception is recorded on one, because its
text can carry either. A failed stage is a span status with fixed text. The user hash lets you
match two traces of one user; it is not secret, since anyone with a list of user ids can hash it.

A request that carries a W3C `traceparent` header is continued: the root span is a child of it, in
the same trace. A header that cannot be read is ignored and the call starts a trace of its own. The
call's `traceparent` (and `tracestate`) also go to the upstream in the `_meta` of the `tools/call`
request, with the upstream call span as the parent, so an upstream that traces can join. Nothing is
sent when tracing is off. Spans are sent in batches every second; a collector that is down costs
nothing but the spans.

## Metrics and the dashboard

`GET /metrics` serves the Prometheus text format. It needs no token, because a scrape sends none,
and it holds no user, session or argument: keep it off the public network all the same. Compose
runs Prometheus (http://localhost:9090) with a job that scrapes `keystone:8080/metrics` every 5
seconds, and Grafana (http://localhost:3000, user `admin`, password `admin`) with the dashboard
**Keystone** in the folder of the same name, loaded from `deploy/grafana/dashboards/keystone.json`.
Edit the file, not the UI: the provisioned dashboard is read-only.

| Metric | Labels | What it counts |
|---|---|---|
| `keystone_tool_calls_total` | `tenant`, `tool`, `effect`, `outcome` | Every call, by what the policy decided (`allow`, `deny`, `require_approval`, or `none` when nothing decided) and how it ended (`ok`, `rejected`, `error`) |
| `keystone_tool_call_duration_seconds` | `stage` | A histogram. `total` is the whole call. Other stages are an interceptor (`policy`, `pinning`, ...), observed once for each of its hooks, and `upstream` |
| `keystone_rejections_total` | `tenant`, `code` | Calls Keystone refused, by `KS_*` code |
| `keystone_upstream_errors_total` | `upstream`, `kind` | `timeout`, `down` (refused without a try, because the upstream is marked down) or `error` |
| `keystone_quarantined_tools` | `tenant` | Tools held for review, as of the last time the registry read the tenant's tools |
| `keystone_policy_eval_seconds` | none | A histogram of the time the policy engine took, for calls and for tool lists |
| `keystone_audit_queue_depth` | none | Audit records accepted and not yet written |
| `keystone_audit_failures_total` | `reason` | `flush_failed`, `record_dropped`, `queue_full`, `shutdown_dropped`, `not_running` (see Audit) |

The labels are bounded on purpose. There is no label for a user, a session or an argument: a label
whose values come from callers would give Prometheus a series for each of them, and metrics are
often less protected than logs. A tenant that is not in the config is `other`, an upstream that
is not is `unknown`, and a call to a tool that does not exist is counted under the tool `unknown`,
whatever name the caller made up.

`keystone_approvals_pending{tenant}` counts the approval requests waiting for a decision. The
approval service sets it when it starts and after each request, decision and sweep.

The metrics of Phases 7 and 8 are declared and nothing sets them yet, so the last row of the
dashboard shows "no data" for them until then: `keystone_sessions_tainted_total`,
`keystone_scan_score`, `keystone_rate_limited_total`, `keystone_budget_spent_usd` and
`keystone_llm_tokens_total`.

The dashboard has five rows: Traffic (calls per second by effect, outcome and tool, rejections by
code), Latency (p50 and p95 of the total, p95 by stage, policy evaluation), Upstreams (errors,
quarantined tools), Audit (queue depth, failures) and the later phases. A test checks that every
metric a panel asks for is declared in `telemetry/metrics.py`, and that every label it groups by
exists.

## Admin API

`/admin/api/v1` is the interface the console and operator scripts use. Every route needs a token
with the `admin` role (401 without a token or with a bad one, 403 without the role), except the
`/approvals` routes, which also take the `approver` role. A route added later is for admins until
it is listed as an approvals route (`admin/auth.py`). Every answer is limited to the tenant of the
token: a record, tool or session of another tenant is not
found (404), so the answer does not say it exists. The OpenAPI schema is at
`/admin/api/v1/openapi.json` and needs no token. The app as a whole serves no schema or docs.

| Route | What it does |
|---|---|
| `GET /audit` | Search the audit log, newest first. Filters: `user`, `agent`, `tool`, `effect`, `outcome`, `since`, `until`, `call_id`. Pages by `cursor` (a `seq`) and `limit` (1 to 200, 50 by default); `next_cursor` is null on the last page. A page never repeats a record, even while calls are being made |
| `GET /audit/{seq}` | One record |
| `GET /audit/verify?last=10000` | Check the hash chain of the newest records (up to 100,000; `keystone audit verify` checks the whole log). The chain runs through every tenant, so the result is about the whole log |
| `GET /tools`, `GET /tools/{name}` | The tenant's tools; a tool's detail with its pending definition, its fingerprint and a diff |
| `POST /tools/{name}/approve-change` | Accept a held definition. The body may carry `expect` (the fingerprint, a prefix will do) and `note` |
| `POST /tools/{name}/disable`, `POST /tools/{name}/enable` | The same as the CLI |
| `GET /upstreams` | Upstreams with status and last sync. A URL is shown without credentials |
| `GET /sessions` | Live sessions of the tenant, read from Redis |
| `GET /policies` | The version in force and the ids of the tenant's policies |
| `POST /policies/reload` | Read the policy files again (see Policies) |
| `GET /approvals` | The tenant's approval requests in one state: `status` (`pending` by default, or `approved`, `rejected`, `expired`, `consumed`) and `limit` (1 to 200, 100 by default). Pending ones come oldest first. Approver or admin |
| `GET /approvals/{id}` | One request, with the last 10 calls of the session that asked (`recent_calls`, as the audit shows them). Approver or admin |
| `POST /approvals/{id}/decision` | `{"approve": true, "note": "..."}`. Approver or admin. See Approvals |

Approving a change through the API calls the same code as `keystone tool approve-change`, with the
same checks and messages: a stale fingerprint is 409 "changed after it was shown", a tool that is
not held is 409, a tool of another tenant is 404. A refusal has the body
`{"error": "...", "reason": "..."}`.

A token for the admin role comes from `scripts/get_token.sh root keystone-cli`. For example:

```bash
TOKEN=$(bash scripts/get_token.sh root keystone-cli)
curl -H "Authorization: Bearer $TOKEN" 'http://localhost:8080/admin/api/v1/audit?tool=bank__transfer'
```

Browsers may call it from `KEYSTONE_CONSOLE_ORIGIN` only. The CORS rule allows `GET` and `POST`
with the `authorization` and `content-type` headers; it does not allow cookies, because the API
takes a bearer token.

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
| Every call gets `KS_DENIED`, "audit unavailable" | The audit writer is unhealthy and `audit.fail_closed` is on. Look for `audit_flush_failed` in the Keystone log: the database is down or refusing the writer. Calls resume within a few seconds of the writer succeeding. |
| A call returns `KS_APPROVAL_PENDING` after 10 seconds | The policy sent it to approval and nobody decided in the hold (`approvals.wait_seconds`). Approve it through the admin API as an approver (`scripts/get_token.sh lena keystone-cli`), then have the agent call `keystone__await_approval`. |
| `KS_DENIED`, "approval not available" | Keystone has no master keys, so it has no approval service. Set `KEYSTONE_MASTER_KEYS`. |
| `keystone__await_approval` says "there is no such approval request for this session" | The id is not this session's: it was made in another session, by another user or agent, in another tenant, or it does not exist. Call the original tool again. |
| An approver gets `403` on a decision | The token lacks the `approver` or `admin` role, or the request is the approver's own. A person cannot decide what they asked for. |
| An approver gets `409` on a decision | The request is no longer pending. The body's `status` says what it is: decided, used, or expired. |
| An approved call ends with `KS_QUARANTINED` or `KS_DENIED` | The call was checked again after its wait and the tool or the policy had changed. The approval is left unused and expires. Fix the cause, and have the agent call the tool again. |
| Keystone does not start: "KEYSTONE_APPROVALS_WEBHOOK_SECRET must be at least 16 characters" | The signing key is too short to trust. Make one with `openssl rand -hex 32`. |
| Keystone does not start: "KEYSTONE_APPROVALS_WEBHOOK_SECRET must be set" | `approvals.webhook_url` is set and the signing key is not in the environment. It is never read from the YAML. |
| Port already in use | Another process holds the port. Set a different one in `.env`. |
| `make check` cannot reach Postgres | Run `make up-core`, then `docker compose -f deploy/docker-compose.yml ps`. |
| `ModuleNotFoundError: keystone` right after `uv sync` (macOS) | A background process flagged `.venv` as hidden, and Python skips hidden `.pth` files. Check with `ls -lO .venv/lib/python3.12/site-packages/keystone.pth`. Set `UV_PROJECT_ENVIRONMENT` to a path outside the repo, for example `$HOME/.cache/keystone-venv`, then run `uv sync`. |
