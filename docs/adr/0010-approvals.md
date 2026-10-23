# ADR-0010: Approvals wait in line, then hand out an id

Status: accepted
Date: 2026-10-23

## Context

Some calls need a person: a transfer over 500, a message to someone outside the company. The
person is usually at the console and answers within a minute, but sometimes not for an hour. An
agent cannot hold an HTTP request open for an hour, and a model that is refused outright cannot
tell "no" from "not yet". Whatever is approved must also be exactly what was asked about, once,
and for a short time, or an approval becomes a permanent key.

## Decision

**Wait in line first.** A call the policy sends to approval is stored as a request and held for
`approvals.wait_seconds` (60 by default). If a person decides in that time the agent sees a slow
call: an approval completes it, a rejection returns `KS_APPROVAL_REJECTED` with the approver's
note.

**Then hand out an id.** If nobody decided, the call ends with `KS_APPROVAL_PENDING`. The id is in
the text, where a model reads it, and in `_meta` as `keystone/approval_id`, with
`keystone/expires_at` and `keystone/next`. The agent calls `keystone__await_approval` with the id
(`wait_seconds`, at most 120) as often as it likes until the request is decided or expires.

**The approval is for one thing.** A request holds the digest of the arguments, the one the audit
log writes as `args_digest`, and the tool, the tenant, the session and the user. It is used by one
`UPDATE` that checks all of them, that the status is `approved` and that it has not expired, so
it is used at most once, and by nothing else. Arguments that differ by a byte have another digest.

**The requester cannot approve.** The user who made a request can never decide it, whatever roles
they hold. An approver or admin of another tenant gets "not found". Both are part of the
`UPDATE`, so there is no gap between the check and the change.

**Time is the database's.** `expires_at` comes from the database clock and the two statements
compare it with `clock_timestamp()`. `now()` is the start of the transaction, and a statement
that waits for a row lock is then judged by a time before it waited; in a test on Postgres 16 it
used an approval after its expiry.

**The id goes on the context after the approval is used.** The pipeline dispatches a call that
needs approval only when `ctx.approval_id` is set (KS-191). The approval slot takes any id off
the context first, uses the approval, and puts the id back only if that worked. A pending call's
id travels in the rejection and never on the context. This is what invariant I7 tests.

**Awaiting re-runs the call under today's rules.** `keystone__await_approval` checks that the
request belongs to the caller's session, waits, and when it is approved decrypts the stored
arguments and runs the original tool through the whole pipeline again: the tool must still be
active, the policy decides again, budgets and rate limits apply. An approval is permission to go
on under the rules that hold now. If an incident tightened them in between, the await is denied.
The inner call leaves an audit record of its own, next to the record of the await.

**Redis wakes, Postgres decides.** A message on `ks:approval:<id>` ends a wait early. It carries
no verdict: a waiter reads the row each time it wakes, and every 2 seconds without a message.
Without Redis the wait polls.

**Keystone's own tools.** `keystone__await_approval` and `keystone__whoami` are served by the
dispatcher for the upstream id `keystone`, which no configured upstream can have (the config
loader, the CLI and the registry refuse it). They get `Decision(allow, source="virtual")`
instead of a Cedar decision, they are listed for every caller, and they pass the same rate limit
and audit slots as any call.

## Consequences

- An approval needs the vault's master keys: the arguments are kept encrypted with them. Without
  `KEYSTONE_MASTER_KEYS` a call that needs approval is refused, as in the stub it replaces.
- A request is lost to an agent that reconnects with a new session: it can no longer await it. The
  call has to be made again, and a person decides again. That is deliberate.
- An approved request that is never used expires after `approvals.ttl_seconds` (15 minutes) and is
  marked expired by the sweeper.
- A held call uses an HTTP request for up to `wait_seconds`. A client whose read timeout is
  shorter than that gives up first and the request stays in the queue until it expires.

## Revisit when

Agents are seen to reconnect often while they wait (the session binding would then move to the
user and agent), or the console needs live updates and polling every 5 seconds is not enough.
