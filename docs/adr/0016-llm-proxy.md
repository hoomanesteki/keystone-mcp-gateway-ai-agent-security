# ADR-0016: Model requests go through Keystone, are priced from the provider's own count, and are booked in the ledger

Status: accepted
Date: 2026-10-23

## Context

A budget on tool calls (ADR-0014) is half a cap. The largest spend of an agent is usually the model,
and an agent that is limited in what its tools cost but can ask a model for anything is not limited.
The story (KS-806) is that a model request gets the identity, the budget and the tracing of a tool
call, so that one place answers "what did this agent cost?".

Four things make a model request different from a tool call. Its price is not known until it ends,
because it depends on the tokens the provider counts. It is often a stream, which has to reach the
caller as it is made and not when it is done. The provider's key must not reach the agent that is
asking. And the SDKs that agents use retry on some statuses and not on others, so the status of a
refusal decides whether the agent asks again.

## Decision

**Two routes, and the agent's SDK is pointed at them.** `POST /llm/anthropic/v1/messages` and
`POST /llm/openai/v1/chat/completions` (`metering/llm_proxy.py`), present only when
`llm_proxy.enabled` is true. An SDK sets its base URL to `http://keystone:8080/llm/anthropic` or
`http://keystone:8080/llm/openai/v1` and uses its Keystone token as the API key. The token is read as
for `/mcp`, from `Authorization: Bearer`, or from `x-api-key`, which is where the Anthropic SDK puts
its key. It gives a principal, and the principal's tenant, user and agent are who the request is
charged to. An optional `X-Keystone-Session` header names an MCP session, which must be the caller's
own (404 if it is unknown, 403 if it is someone else's), and the cost is added to that session's spend.

**No policy decides who may call a model.** Any agent of the tenant that owns the provider keys, that
can sign in, may, and its budgets are the limit. A policy on models (this agent may use the small
model only) is a Cedar schema change, and v1 does not make one.

**The provider keys are credentials in the vault.** `llm_anthropic` and `llm_openai` are
pseudo-upstreams: rows in `upstreams` with a static credential, so that the vault, which already
keeps what Keystone sends on a caller's behalf, keeps these too. The ids are reserved (no config can
use them for a tool server), the rows are `disabled` from the start so that nothing syncs, probes or
lists them, and the admin API and the CLI leave them out. At each start the key is read from the
variable that `llm_proxy.<provider>.api_key_env` names (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) and
stored through the same code as `keystone cred set`; a variable that is not set leaves the stored
key, so a key set by hand stays. A provider whose `api_key_env` is null is sent the key that is
stored for it, if any, and is not refused when there is none. An upstream
id is unique across tenants, so one tenant owns each key: `llm_proxy.tenant`, which with one tenant
in the config is that one. A caller of another tenant is refused (403 `KS_DENIED`) and cannot spend
another tenant's key.

Anthropic wants the key in `x-api-key` and OpenAI as `Authorization: Bearer`. The vault registers a
decrypted value with the log scrubber as it is stored, which for a bearer header is the whole
`Bearer sk-...`, so the proxy registers the bare key too.

**The price list is the owner's.** `pricing.yaml` maps a model to `input_per_mtok` and
`output_per_mtok` (dollars for each million tokens), and optionally `cache_read_per_mtok` and
`cache_write_per_mtok`, which default to the input price (pricing a cached token as fresh can only
overstate). A name ending in `*` covers a family; the longest match wins. Nothing in this repository
claims to know a provider's prices: `pricing.example.yaml` is labelled as example numbers that are not
real, the tests use fake prices, and the compose stack mounts `deploy/pricing.compose.yaml`, which
prices the fake models. The file is read at startup, and a missing or empty one stops it with a
message that says what to do. A model with no entry is refused with 400 `KS_MODEL_NOT_PRICED`,
because a request that cannot be costed cannot be held to a budget; `llm_proxy.allow_unpriced`
lets it through at no cost and logs a warning each time.

**The pre-check is an estimate, and it refuses with 402.** The cost of a request is not known before
it is made, so the budget is checked against its worst case: the body at four bytes a token as
input, and `max_tokens` of output (times `n` for OpenAI; 4096 when a request does not say, the
default `llm_proxy.default_max_tokens`). `BudgetService.check` is the same call the budget slot
makes for a tool, so the tenant, user and agent budgets and the day and month windows apply
unchanged. A request that would take any budget over its limit is refused before the provider sees
it, with `scope`, `window`, `limit_usd`, `spent_usd`, `estimate_usd` and `resets_at`. The status is
402 and not 429: the Anthropic and OpenAI SDKs retry 429 and 5xx, and a refusal that will not
change in a minute must not be retried. A budget service that cannot be read refuses the request
with 503, because a request that cannot be checked is not a request with room to spend.

**What goes to the provider.** The URL is built from `llm_proxy.<provider>.base_url` and a fixed
path; a caller picks neither. The body is sent as it came, except that an OpenAI stream gets
`stream_options.include_usage` set to true whatever the caller said (the other options it set stay),
because the cost is made from the count and OpenAI gives none otherwise. The one visible effect is
that the caller's stream ends with a chunk with an empty `choices` list. The headers are a short
list: `content-type: application/json`, the caller's `accept`, `anthropic-version` and
`anthropic-beta`, `accept-encoding: identity` so that the bytes that pass are the bytes the usage is
read from, a `user-agent`, and the key. The caller's token, its cookies and every other header stay
behind. Redirects are not followed.

**A stream passes through unchanged, and is read on the way.** Each chunk is handed to the caller as
it arrives and fed to a reader that finds the usage: Anthropic's `message_start` (the input tokens
and cache tokens) and `message_delta` (the output counted up to the end), OpenAI's last chunk. The
reader keeps the larger of each count, never raises, and drops a line longer than 1 MB. The count is
the provider's; the proxy never counts tokens, except for the estimate above.

**The cost is booked before the last byte.** When an answer ends, the proxy writes a `kind="llm"` row
in `spend_ledger` (`ref` is the request id, also sent back as `x-keystone-request-id`), moves the
counters of the budgets that apply, adds the cost to the linked session, counts the tokens on
`keystone_llm_tokens_total{tenant,model,direction}` and ends a `keystone.llm_call` span with
`gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`
and the cost. All of it happens before the end of the response is sent, so a caller that has the
whole answer can ask what it cost and find the row. The `model` label is the name of the price entry
that applied (which may be a family such as `some-family-*`) or `unpriced`, so the number of series is
the size of the price file and not the number of names callers invent. The ledger row stores the model
the caller asked for.

**What is booked when the usage is not whole.** The ledger gets what was counted, and a warning is
logged (`llm_usage_incomplete`, with a reason).

| How it ended | Booked |
|---|---|
| The stream ends with the provider's final count | the count |
| It ends without one (Anthropic: no `message_delta`; OpenAI: no usage chunk) | the tokens that were counted, which is the input and a placeholder of one output token for Anthropic and nothing for OpenAI |
| The provider breaks the stream | what was counted; the caller's connection is broken too, so it sees an error and not a stream that looks finished |
| The caller leaves a stream | what was counted; the proxy closes the provider's connection at once, to stop the provider generating |
| The caller leaves an answer that is not a stream | the whole count: by the time headers arrive the provider has finished and charges for it, so the proxy reads the rest (5 s at most) to learn the cost |

The last row matters. Without it a caller could hang up on every request and never be charged.

**A provider's error goes back as it came.** Its status, its body and a few headers (`content-type`,
`retry-after`, `request-id`, `cache-control`) reach the caller, so an SDK's retry logic sees a real 429.
The body is read whole (1 MB at most) and the key is replaced by `[redacted]` in it and in those
headers, since some APIs repeat the credential they were given in a refusal. A request that the
provider refused costs nothing and is not booked. Keystone's own refusals are
`{"error": {"type": "keystone", "code": "KS_...", "message": "..."}}` with the facts of the refusal
beside the code.

## Consequences

- The key is in memory for the length of a request and in Keystone's logs and responses nowhere:
  the tests send a canary key through successes, streams and provider errors that echo it, and
  search the responses, logs, spans, `/metrics` and the admin API for it.
- A request is refused if it might cost more than a budget has left, and not only if it does. A
  `max_tokens` of 64,000 on an expensive model has an estimate of several dollars whatever the
  answer turns out to be. The estimate is what makes the check possible, and a caller that sets a
  smaller `max_tokens` is let in.
- The check is not a reservation, as for tools (ADR-0014): requests in flight together are checked
  against the same spend, so a cap is overshot by what they cost.
- A caller that leaves a stream is charged for the tokens counted when it left, and the provider
  charges for the tokens generated until it noticed the connection was closed. The difference is the
  last few events.
- A stream that the provider cuts, or that never reports a count, costs less in the ledger than it
  did at the provider. The warning is the record that this happened; the ledger row keeps `NULL`
  tokens when nothing was counted.
- Prices go out of date. A price that is too low under-counts spend, and nothing in Keystone can tell.
  The owner keeps the file current, and a model that is not in it is refused and not guessed at.
- A request holds a connection to the provider for as long as it lasts, up to 600 seconds between
  bytes. At most 200 are open; a request that cannot get one in 10 seconds is told 503 and to try
  again.
- The cost is tokens only. A charge that a provider makes for something else, such as a server-side
  search tool that is billed for each use, is not counted, and nothing stops a caller from asking for
  one.
- A request is not rate limited, writes no `audit_events` row, and is not checked by a policy. Its
  record is the ledger row, the span and the log line. Prompts and answers are not logged or put on
  a span.
- A request for tenant B cannot use tenant A's key. A deployment with a key for each tenant needs
  tenant-scoped upstream ids, which are not in v1.

## Revisit when

A tenant must have its own provider key, or a policy must decide which agent may use which model
(Cedar over the model name, which is in the request). Or when the estimate refuses requests that a
deployment cares about: a reservation that is given back at the end, or a per-model ceiling for
`max_tokens`. Or when a provider adds a third API shape (Anthropic's batch API, OpenAI's responses
API): each is a route, a usage reader and a path.
