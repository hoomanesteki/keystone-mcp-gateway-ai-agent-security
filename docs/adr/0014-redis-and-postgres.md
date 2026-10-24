# ADR-0014: Redis holds hot state, Postgres holds the record, and budgets are rebuilt from it

Status: accepted
Date: 2026-10-23

## Context

Three things in Keystone change on every call: a session's flags and spend (ADR-0015), the buckets
that limit how fast calls come (KS-804), and the totals that spending limits are checked against
(KS-805). A call reads them before it runs, so they have to be fast. Redis answers in a fraction
of a millisecond; Postgres in a millisecond or more, with a transaction around it.

Redis is also a cache. It can be restarted with nothing on disk, flushed by mistake, or lost with
the host. If a total of dollars lived only there, a restart would give everyone back the money they
had spent that day, and a cap that a restart clears is not a cap.

## Decision

**Postgres is the record. Redis is a fast copy of what the record can prove, and nothing in Redis is
believed over it.**

| What | Where it is true | What Redis holds |
|---|---|---|
| Money spent | `spend_ledger`, one row for each priced tool call and each model request | `ks:spend:{tenant}:{scope}:{id}:{window}:{start}`, one total for each budget and window |
| Limits on spend | `budgets`, from the config at each start | nothing: they are read from the table, and again every 30 seconds |
| Who may make how many calls | the config (`rate_limits`) | `ks:rl:{scope}:{tenant}:{id}`, a token bucket for each, which expires when it would be full |
| A session's flags and taint | a Redis hash (ADR-0015), and a row for the durable reference | the hash itself |

A bucket and a session are state that a restart may lose without harm worth a second system: a
bucket comes back full, and a session is started again. Money is different, so it has a ledger.

**The ledger.** A row is written when a call that has a price has run (the metering slot), and when a
model request has ended (the proxy). `(kind, ref)` is unique, so a record that is made twice counts
once. The application's database role may add rows and read them and may not change or delete them,
like the audit log: a gateway that is compromised cannot take spend back out. A refund will be a row
of its own.

**The counters.** The pre-check reads the totals of every budget that applies to the caller in one
`MGET`, and a record moves them with `INCRBYFLOAT` inside one transaction with the expiry. Redis keeps
a decimal text for the result, so three cents is `0.03` and not a float's `0.030000000000000002`;
Keystone reads the text as a Decimal and works in nine decimal places. A counter expires a day after
its window ends. The ledger is written first and the counters after, so a counter is never ahead of
what the ledger can prove.

**Three ways the counters are put right.**

1. At each start, every budget's counter for the window it is in is raised to the ledger's total. A
   script does the raising and never lowers: a second Keystone that already counted, or a call that
   was recorded between the read and the write, is not undone.
2. A counter that is missing when a pre-check needs it (Redis was restarted or flushed while
   Keystone ran) is read from the ledger on the spot and stored, in the same way. So a Redis restart
   cannot reset anyone's spend to zero, and no one has to restart Keystone to repair it. The cost is
   one query for each budget and window the first time it is read after the loss.
3. If the rebuild at start fails, Keystone starts anyway and logs it. The counters are a cache, and
   the pre-check does what the rebuild would have done.

**Where a charge is counted.** In the window its call began in, not the one it ended in. A call that
began at 23:59:59 and ended at 00:00:03 is charged to the day it began. Days run from 00:00 UTC to the
next, and months from the first at 00:00 UTC.

**The check is not a reservation.** The pre-check is `spent + price > limit`, read before the call
and not held. Calls that are checked at the same moment all see the same spend, and each may pass
when only one fits. A cap is overshot by at most the price of the calls that were in flight together,
and the next call is refused. A reservation would take the price at the check and give it back
whenever a later slot refuses the call or the upstream fails, and the pipeline has no point at which
to give it back. A model request is checked against an estimate of its worst case instead (KS-806):
its price is not known until the end, and the estimate is what makes the check worth making.

**A tool with no price is never held by a budget.** There is nothing to project, and a cap on money
is not a cap on calls (that is the rate limit).

## Consequences

- Each priced call costs one insert into Postgres on its way out, and each call to a tool for which a
  budget applies costs one Redis read on its way in. The first is the price of a record that cannot be
  lost; a free call pays neither.
- Redis can be flushed at any moment, and the only visible effect is a read of the ledger. Postgres
  being down stops a priced call from being recorded: the output is withheld, as for any slot that
  fails after the dispatch, and the audit record shows the price.
- A budget exists only while it is in the config. There is no write API for budgets in v1; the table
  mirrors the file at each start, and a budget that left the file is removed and logged.
- The ledger grows by a row for each priced call and each model request, with three indexes. At ten
  thousand priced calls a day that is a few megabytes a month. Nothing prunes it: it is the record.
- Two processes that share Redis share the totals. Two that share nothing (no Redis, each with the
  in-memory counters) enforce the cap each for itself.
- The gauge `keystone_budget_spent_usd{tenant,scope}` is the highest spend in the current window among
  the budgets of one scope, as this process has seen it. It is not a sum, because the budgets of a
  scope (one for each user) do not add up to anything a person asked for.

## Revisit when

A budget must be changed while Keystone runs, or by someone who is not an operator with a config
file: it gets an admin route and a row that records who changed it. Or when the overshoot matters
(a cap that is a contract and not a guard): a reservation, with a hook in the pipeline for giving it
back.
