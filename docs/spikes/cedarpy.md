# Spike: cedarpy capabilities (KS-401)

I needed to know what `cedarpy` can do before building the policy engine on it. This page answers
the five questions in the story with code I ran, and lists three things I found that the engine
design depends on. The behaviors are kept as tests in `tests/unit/test_cedar_spike.py`, so a
`cedarpy` upgrade that changes one of them fails there first, with the behavior named.

## Versions

| Item | Version | Note |
|---|---|---|
| cedarpy | 4.12.2 | The latest release on 2026-10-22 (published 2026-10-14). It wraps Cedar 4.12.0, and its version number follows the engine's major and minor. |
| Python | 3.12.13 | |
| Wheels | cp312 | macOS arm64 and x86_64, Linux x86_64 and aarch64, Windows (`uv.lock` lists all five), so the Docker image installs without a Rust toolchain. |
| Runtime dependencies | none | |

I read the installed source in `site-packages/cedarpy` (`__init__.py`, `_internal.pyi`, `pst.py`)
and the package README, then ran every snippet below. The package ships `py.typed`, so mypy reads
its signatures and needs no `ignore_missing_imports` override. The README describes more than the
plan assumed: parsed handles for policies, schemas and entities, and an `@id` map in the
diagnostics.

## 1. The call

```python
from cedarpy import PolicySet, Schema, is_authorized

schema = Schema.from_str(cedarschema_text)  # parse once
policies = PolicySet.from_str(policy_text)  # parse once
result = is_authorized(request, policies, entities, schema=schema)
```

- `request` is a dict. `principal`, `action` and `resource` are `{"type": ..., "id": ...}` dicts or
  Cedar strings such as `'Keystone::User::"acme:olivia"'`, and `context` is a dict. I use the dict
  form: the ids come from tokens and tool names, and the string form would need Cedar escaping.
- `entities` is a list of dicts, a JSON string or a parsed `Entities` handle. A reference to
  another entity inside `attrs` is `{"__entity": {"type": ..., "id": ...}}`, and `parents` holds
  `{"type": ..., "id": ...}`.
- The result has `decision` (`Allow`, `Deny` or `NoDecision`), `allowed`, `diagnostics.reasons`,
  `diagnostics.errors`, `diagnostics.id_annotations_by_reason` and `metrics` (microseconds spent
  parsing and evaluating).
- Passing text for the policies or the schema parses it again on every call. A `PolicySet` or
  `Schema` handle skips that, and `metrics["policies_pre_parsed"]` says so (the latency section
  shows the size of the difference).

**The human-readable `.cedarschema` file is accepted as it is.** `Schema.from_str` reads the
plan's schema, comments and trailing commas included, and `Schema.from_json_str` is there for the
JSON form. Nothing has to be converted, so `policies/schema.cedarschema` is the one source.

## 2. Determining policies and the `@id` annotation

Cedar names a policy parsed from text by its position, `policy0`, `policy1` and so on, in the
order they appear in the text it was given. `diagnostics.reasons` holds those names:

| Case | `decision` | `reasons` |
|---|---|---|
| One or more permits matched, no forbid | `Allow` | every permit that matched |
| A forbid matched | `Deny` | the forbids that matched, and only those |
| Nothing matched | `Deny` | empty |
| A permit and a forbid matched | `Deny` | the forbid |

The empty list is how a default deny shows. The mapping back to `@id` is built in:
`diagnostics.id_annotations_by_reason` maps each reported name to the policy's `@id`, for example
`{"policy2": "deny-cross-tenant"}`. A policy without an `@id` is missing from that map, so the
loader rejects such a policy and a reason is never a bare `policy3`.

The route the plan suggested works as well. `policies_to_json_str(text)` returns
`{"staticPolicies": {"policy0": {"effect": "permit", "annotations": {"id": ...}, ...}}}`, numbered
the same way. The loader reads each policy's `@id` and effect from it once, at load time (it takes
2.6 ms for 50 policies, which is why it is not done per call). The effect matters because the
approval set may hold permits only. The kept test checks that both routes agree.

Messages in `diagnostics.errors` name the positional id (``error while evaluating policy
`policy0` ``), not the `@id`. The engine maps them before it logs them.

## 3. Validation

`validate_policies(text, schema)` returns `validation_passed` and `errors`, each with a
`policy_id`, and `id_annotations_by_policy_id` maps those to the `@id`. It catches:

| Mistake | Error |
|---|---|
| A misspelled attribute (`resource.rsik_level`) | attribute `rsik_level` on entity type `Keystone::Tool` not found |
| An optional attribute read without `has` (`context.args.amount > 1`) | unable to guarantee safety of access to optional attribute `args.amount` |
| A type error (`context.agent_trust > 1`) | expected Long but saw String |
| An unknown entity type or action | unrecognized entity type, unrecognized action |

It takes 1.1 ms for 50 policies. It does not check that a policy has an `@id` (a policy without
one passes), that ids are unique (two policies with one `@id` pass), or that the ids look like
kebab case. The loader does those. A syntax error is raised by `PolicySet.from_str` as a
`ValueError` with a bare message such as `unexpected end of input`, with no file and no line, so
the loader parses each file on its own to say which file is broken.

**Request validation** is what passing `schema=` to `is_authorized` adds. A context that misses a
field, has an unknown key or has a field of the wrong type, and an entity attribute of the wrong
type, give `NoDecision` with `diagnostics.errors` (`failed to build request: ...`). Without the
schema the same mistakes are not noticed unless a policy happens to read the field.

## 4. Sets, entity references and the name `tags`

| Check | Result |
|---|---|
| `Set<String>` attribute on an entity (`tags`), as a JSON array | works; `resource.tags.contains("external_effect")` validates and evaluates |
| `Set<String>` in the context (`session_flags`) | works; `context.session_flags.contains("reads_untrusted")` |
| Entity reference attribute (`tenant`) | works with `{"__entity": {...}}`, and without the wrapper when a schema is given |
| `principal in Keystone::Group::"operators"` through `parents` | works |
| Optional record field (`args.amount?`) with `context.args has amount` | works; reading it without `has` fails validation |
| The rule of two permit (needs both flags and the tag) | matches with both flags and the tag, not with one flag or without the tag |

**The attribute name `tags` does not collide with Cedar 4 entity tags.** Entity tags are a
separate field of the entity JSON, next to `attrs`, declared in a schema with a `tags` clause
after the attribute record. An attribute named `tags` inside the record is an ordinary
identifier: the schema parses, the policies validate, and the evaluation reads it. `tags` is not
a reserved word in the policy language. The one trap is the top-level field: an entity that
carries `"tags": {...}` next to `attrs` is refused under this schema, because the schema declares
no entity tags (`NoDecision`). The entity builder therefore writes the tool's tags into
`attrs.tags` only. `policies/schema.cedarschema` stays as the plan has it, and the contract does
not change.

## 5. Latency

50 policies (the plan's six plus 44 of the shapes a tenant writes: per-group permits, per-tool
forbids on the hour, per-tool approvals on an amount), 20 entities, 10,000 evaluations after 200
warm-up calls, timed around the whole `is_authorized` call from Python. That includes encoding
the context and the entities to JSON, which `cedarpy` does on every call.

Apple M4 (10 cores), macOS 26.7.1, Python 3.12.13, cedarpy 4.12.2, the Docker stack idle. Two
runs agreed to within 0.03 ms at p50.

| What is passed on each call | p50 | p95 | p99 |
|---|---|---|---|
| A. Policies, schema and entities all as text or lists | 1.22 ms | 1.32 ms | 2.99 ms |
| B. `PolicySet` handle, schema as text | 0.58 ms | 0.63 ms | 1.66 ms |
| C. `PolicySet` and `Schema` handles, entities as a list | 0.24 ms | 0.25 ms | 0.27 ms |
| D. As C, without the schema | 0.24 ms | 0.25 ms | 0.53 ms |
| E. All three as handles (entities parsed once) | 0.075 ms | 0.079 ms | 0.088 ms |

Parsing the policies and the schema is most of the cost, so the engine keeps handles (row C).
Row E is not available to it, because the entities differ on every call. An earlier run of row C
on the same machine, with other processes running, gave 0.47 ms at p50 and 0.50 ms at p95. I do
not know the cause, but it says to measure again where the numbers matter. Evaluating the
engine's two passes through the gateway is measured in KS-404 and recorded at the end of this
page.

Load-time costs at p50 for the same 50 policies: `Schema.from_str` 0.32 ms, `PolicySet.from_str`
0.62 ms, `validate_policies` 1.1 ms, `policies_to_json_str` 2.6 ms.

For a tool list of 60 tools, 60 separate calls took 5.0 ms at p50 (5.2 ms at p95) and one
`is_authorized_batch` call took 3.5 ms at p50 (6.0 ms at p95). The batch call is not worth the
extra code. The tool-list cache of KS-406 covers the rest.

## Three findings the engine design depends on

1. **An error inside a policy does not stop the decision.** Cedar skips a policy that fails to
   evaluate and reports it in `diagnostics.errors`. When that policy is a `forbid`, the decision
   is still `Allow`: I wrote a forbid that reads a missing attribute next to a plain permit and
   got `Allow` with one error. When it is a permit in the approval set, the call is allowed
   without the approval. The engine therefore treats any entry in `errors`, in either pass, as a
   failure and denies with `policy-error`.
2. **`NoDecision` is not a decision.** A context or an entity that does not fit the schema, an
   action the schema does not know, a principal that is not a valid id, and a policy text that
   does not parse all give `NoDecision`, with the reason in `errors`. The engine reads anything
   other than a clean `Allow` or `Deny` as a deny. An entity that is simply missing from the list
   is different: Cedar evaluates anyway, every policy that reads the entity reports an error, and
   the decision can still be `Allow` through a permit that does not read it (finding 1).
3. **An empty policy set denies.** `PolicySet.from_str("")` loads, and every request is a `Deny`
   with no reasons. Invariant I6 holds even if the loader finds no files.

## Measured in the engine (KS-404 to KS-408)

`scripts/bench_policy.py` times `CedarPolicyEngine.evaluate`, the call the policy slot makes: it
builds the five entities of the call, asks the access set and, when that allows, the approval
set. 10,000 runs after 200 warm-up calls, on the machine above with the Docker stack idle, run
twice. The 50-policy tenant is the plan's four access policies plus 46 of the shapes a team
writes, split between its two sets. The last row adds what the policy slot does around the engine:
it reads the arguments with the extractor and builds the context.

| Set | Policies | Decision | p50 | p95 (worst of two runs) | p99 (worst of two runs) |
|---|---|---|---|---|---|
| The shipped pack, acme's sets | 6 | allow | 0.16 ms | 0.16 ms | 0.18 ms |
| A tenant with 50 policies, nothing asks for approval | 50 | allow | 0.18 ms | 0.29 ms | 0.55 ms |
| The same tenant, a transfer over the limit | 50 | require approval | 0.18 ms | 0.20 ms | 0.49 ms |
| The shipped pack, the whole slot (extract, context, decide) | 6 | require approval | 0.16 ms | 0.17 ms | 0.22 ms |

Both passes together cost less than one pass in the spike (0.24 ms for 50 policies and 20
entities), because each pass holds only its own set and a call has five entities, not twenty. The
slot around the engine adds under 0.01 ms. The plan's budget is a p95 under 5 ms in CI
(`test_eval_latency_budget`), which is 17 times the worst figure here; a hosted runner is slower,
and the margin is for that. The two runs differ most in the tail: one run of the 50-policy
allowed case had a p95 of 0.20 ms and the other 0.29 ms.

## What I did not test

- Policy templates, partial evaluation and the `pst` module. The loader and the engine use none
  of them.
- Calls from several threads. The gateway evaluates on its event loop, one call at a time, and an
  evaluation holds the GIL for about 0.25 ms.
- Linux timings. The KS-404 budget test (p95 under 5 ms) runs in CI.

## What this means for the next stories

- KS-402: the schema file is used as it is, through `Schema.from_str`. Entities and contexts are
  checked against it in the tests, and `attrs.tags` is the only place a tool's tags go.
- KS-403: one adapter module imports `cedarpy`. The loader parses each file alone for the
  message, checks `@id` presence, uniqueness and form itself, runs `validate_policies` on the
  tenant's set, rejects a `forbid` in the approval set, and keeps `PolicySet` and `Schema`
  handles.
- KS-404: the access pass and the approval pass each use one handle. A non-empty `errors` or a
  decision other than `Allow` or `Deny` is a deny with `policy-error`.
