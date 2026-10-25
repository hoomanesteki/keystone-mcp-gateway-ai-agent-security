# ADR-0019: What the performance run changed, and what it left alone

Status: accepted
Date: 2026-10-25

## Context

The run of KS-903 missed M5 and M6 and `docs/progress.md` ("Found") says why: sessions that
opened together were refused by a Redis pool of 100 connections, the classifier took every core of
a container and starved the event loop, and a call cost 15.3 ms of CPU on a loop that is one core.
KS-992 fixes what the numbers pointed at and leaves the rest. This record says what each change
trades, because three of them make the gateway wait for something it used to ask at once.

## Decisions

**One blocking Redis pool, 500 connections, a wait of 2 s.** `redis_pool_size` and
`redis_pool_timeout_s` (`KEYSTONE_REDIS_POOL_SIZE`, `KEYSTONE_REDIS_POOL_TIMEOUT_S`). Sessions,
rate limits, budgets, the policy list cache and the approval pub/sub already shared one client; it
now has a pool that waits for a connection, so a burst is served and not refused. A caller that
waits more than 2 s still fails, and a call that cannot read its session is still refused: the safe
answer did not change, only how large a burst it takes to reach it.

**The classifier runs in as many places as the CPUs allow, less one, and a scan that finds none
free skips the model.** The container was limited to 4 CPUs on a host of 10; torch and the thread
limit of the classifier both counted the 10. The model's threads took the container's quota, the
kernel throttled all of it, the health probes of every upstream (used or not) timed out in the same
second, and calls failed as `upstream echo is down`. The places and the threads of each scan now come
from the CPUs the process may use (the cgroup limit counts), keeping one for the event loop:
`scanner.classifier_concurrency` and `scanner.classifier_threads` override it. A scan that finds all
places taken does not queue: it records `model="busy"` and the rules decide, like a timeout.
Waiting would have spent the call's time on a queue that the model, at 160 ms or more per scan on 3
threads, cannot clear. Under load most scans are therefore rules only, and the share is in the
results. `busy` is not an error and does not call `on_error`.

**The opened credential of an upstream is kept for 60 s** (`credential_cache_ttl_s`). Every call read
the row and decrypted it. A `set`, `seed` or `rotate_keys` made in the gateway process drops the
entries at once; a `keystone cred set` made by the CLI is another process and is seen when the entry
expires. A credential taken away through the CLI can therefore be sent for up to 60 s. `0` turns the
cache off. The cost is the staleness of a revoked credential, not of a decision: policy, pinning and
the approvals still run on every call.

**Hooks that do nothing have no span.** 9 of the 18 hooks of a call are `return None`; a span costs
about a tenth of a call's CPU between making it, ending it and encoding it for the exporter. They are
marked `noop_hook`, keep their timing and their counter in `keystone_tool_call_duration_seconds`,
and a test holds that a marked function has nothing in it. A trace now has 12 spans and not 21.

**The validator of an input schema is built once per schema hash.** It is used only when the schema
it was made from is the schema in hand, so a hash cannot be the reason a call is checked against the
wrong schema.

**A call to a tool that does not exist takes a token from the principal's buckets.** It was audited
and never limited. When a bucket is empty the answer is `KS_RATE_LIMITED`.

## Left alone, on purpose

**The pinning slot still asks Postgres on every call.** Serving the status from the registry's
snapshot (2 s old at most) would have saved about 0.6 ms of CPU a call. `test_i4` makes a tool
unavailable behind the gateway's back and calls it at once, "the cache expiring must not be what
stops them", and KS-691 re-checks a call that waited for the same reason. Taking the read from the
cache is a change to invariant I4 and not a performance fix, so it is the owner's to decide. What
changed is that the read no longer opens a transaction (BEGIN and ROLLBACK around one SELECT).

**`canonical_json` of the arguments is still computed where it is used.** It is 0.5% of the CPU of a
call, and sharing the bytes between the size check, the audit digest and the approval digest means a
cache that a slot changing `ctx.arguments` would have to know about.

**One uvicorn worker.** MCP sessions live in the process.

## Consequences

CPU per call, the 200-session numbers and the share of scans the model skipped are in
`docs/results.md`. Nothing here moves the work off the event loop: one process is one core, so
calls a second per process are bounded by CPU per call, and a second core needs a second process
behind a router that keeps a session on the process that opened it.

## Result

Measured at the tip of the branch (`eval/results/perf-2026-10-24b.json`). With the scanner off at 1 KB one process serves 78.3 calls a second with one session (was 56.8) and 87.7 with 200 sessions (was 63.9), a call costs 11.1 ms of CPU (was 15.3), and no call of 4,000 failed at 200 sessions (was 130). M5 at 200 sessions is not met: 88 calls a second against the 1,020 the target needs. The scans did not reach the model, and ADR-0019 does not claim they did: on this host a scan took 0.6 to 1.5 s inside the container, against a wait of 300 ms, so the model answered none and M6 is not measured. The "busy" rule is what keeps that from costing a wait.

