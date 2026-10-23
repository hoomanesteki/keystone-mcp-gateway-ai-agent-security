# ADR-0006: Cedar through cedarpy, evaluated in process

Status: accepted
Date: 2026-10-22

## Context

Every tool call needs a decision (allow, deny or require approval) with reasons a person can
read. The rules have to live in files, be reviewed like code and be tested in CI, and a mistake
in them has to fail loudly. The plan chose Cedar, called from Python through `cedarpy`, and named
OPA as a sidecar as the fallback if `cedarpy` could not load the schema or return policy ids.

Cedar has a typed schema, so a misspelled attribute or an unsafe read of an optional field is
rejected when the policies load. It is built to be analyzed, and it evaluates in the gateway's own
process, so a decision costs a function call and not a network hop. OPA is more general, but it
needs a sidecar, and Rego has no schema that catches those mistakes at load time.

The spike (`docs/spikes/cedarpy.md`, KS-401) tested the four things the fallback depends on
against cedarpy 4.12.2, which wraps Cedar 4.12.0. All four work.

## Decision

- Cedar through `cedarpy` 4.12.2, in process. The OPA fallback is not needed.
- One adapter module, `keystone.policy.cedar`, is the only code that imports `cedarpy`. The rest
  of the policy package works with typed values the adapter returns, and mypy strict covers it.
- `policies/schema.cedarschema` is read as text through `Schema.from_str`. It is never converted
  to JSON, and it is the single source of the schema.
- Policies and the schema are parsed once, when the set loads, into `PolicySet` and `Schema`
  handles that every evaluation reuses. Entities and the context are built for each call. Request
  validation against the schema stays on for every call.
- The two sets per tenant of plan section 3.8 (access and approval) each get a handle of their
  own. A reason is the policy's `@id`, read from `diagnostics.id_annotations_by_reason`.
- Fail closed. Any `errors` entry in either pass, a decision of `NoDecision`, an exception and an
  empty or missing set all end in a deny with the reason `policy-error` or `default-deny`. The
  only way to an allow is a clean `Allow` from the access pass and a clean answer from the
  approval pass.
- Request ids and entity ids go to Cedar as `{"type": ..., "id": ...}` dicts, never built into a
  Cedar string, because the ids come from tokens and tool names.
- The attribute `tags` on `Tool` stays. It does not collide with Cedar 4 entity tags, and the
  entity builder writes tags under `attrs` only, never in the entity's own `tags` field. The
  schema file does not change.

## Consequences

- Cedar skips a policy that fails to evaluate and still returns `Allow` when another permit
  matches. An erroring `forbid` would silently not forbid, so the engine's extra check on `errors`
  is part of the design and has its own tests.
- Cedar does not require an `@id` and does not mind duplicates. The loader requires one on every
  policy, in kebab case, unique within a tenant's combined set, and it rejects a `forbid` in the
  approval set, which can only upgrade an allow.
- A syntax error carries no file or line, so the loader parses each file on its own.
- `cedarpy` is a wrapper that AWS and the Cedar team do not support, so a release can lag the
  engine. ADR-0002 pins it, and the adapter keeps the exposure to one file. The tests in
  `tests/unit/test_cedar_spike.py` name each behavior the engine relies on.
- An evaluation costs about 0.25 ms for 50 policies and 20 entities on a laptop (the spike has
  the table). A call that is allowed runs two passes. The hard budget is a p95 under 5 ms in CI.

## Revisit when

`cedarpy` can no longer load the human-readable schema, return the `@id` of a determining policy
or validate policies against the schema, in which case OPA as a sidecar with Rego versions of the
default policies is the fallback and KS-402 to KS-404 are rewritten. Also when the p95 budget is
missed, or a Cedar release changes how errors in a policy are reported.
