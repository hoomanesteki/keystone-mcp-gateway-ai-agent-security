# ADR-0015: A session changes by merging

Status: accepted
Date: 2026-10-23

## Context

Gate 6 found a gap that Phase 7 would have turned into a way around the defense. When a call
ended, the gateway saved the whole session as it was when the call began. A call held for
approval keeps that copy for up to 300 seconds (`approvals.wait_seconds`). In that time another
call of the same session can read an untrusted email, find an injection and taint the session.
When the held call ends it writes the old copy back and the taint is gone. Holding one call open
was a way to clear the taint of another.

Counters fail the same way in another shape: two calls that both read `call_count` 5 both save 6.

Nothing set a flag or a taint before Phase 7, so nothing was wrong yet. The stories that set them
need a store that cannot lose them, so this one comes first.

## Decision

**Every change adds, and none removes.**

| Field | Rule |
|---|---|
| `flags` | A set union. A flag is added and never taken away. |
| `tainted` | Can become true. Nothing sets it back to false, a save included. |
| `call_count` | An atomic increment. |
| `spent_usd` | An atomic increment by a decimal amount. |

**The store gets atomic methods.** `SessionStore` is the contract of plan section 3.6, and this
story changes it. It keeps `create`, `get` and `save` and adds:

| Method | What it does |
|---|---|
| `add_flags(session_id, flags)` | Adds the flags to those the session has. |
| `mark_tainted(session_id)` | Sets the taint. |
| `incr_calls(session_id, count=1)` | Adds to `call_count`. |
| `add_spend(session_id, usd)` | Adds to `spent_usd`. |
| `touch(session_id)` | Restarts the session's clock and changes nothing else. |

The four that change something return the session as it is afterwards, with whatever other calls
recorded, or `None` when there is no such session: it expired, or it was never stored. A change
to a session that is gone stores nothing, so a late write cannot leave behind a taint with no
session to belong to. A count that is negative, a spend that is negative or not finite, and a
flag that is not a `ToolTag` raise `ValueError` before anything changes.

`save` stays and is a merge. It adds the copy's flags, sets the taint if the copy has it, and
raises a counter to the copy's value if that is higher. A copy that says "not tainted" cannot
clear a taint, and a copy with a lower count cannot lower it. It does not bring back a session
that is gone. A call counts with `incr_calls` and `add_spend`, never by adding to its copy and
saving it: two copies that each add one and save would count once.

**A session is one Redis hash.** `ks:sess:{id}` was a JSON string. It is a hash now, with
`session_id`, `principal` (JSON) and `created_at`, and one field for each thing that changes:
`flag:<tag>` for each flag, `tainted`, `call_count` and `spent_usd`. A flag in a field of its own
makes adding it one `HSETNX`, which is a union. The counters are `HINCRBY` and `HINCRBYFLOAT`.
Two Lua scripts do the work: one creates the session if none is there, and one applies a change
if the session exists, restarts its 24 hour clock and returns the hash. The check for existence
and the change are one step, so a late write never makes a key of its own.

I did not keep the JSON document and edit it in a script, because Redis's `cjson` cannot tell an
empty array from an empty object. On Redis 7.4, decoding `{"a":[]}` and encoding it again gives
`{"a":{}}`, and a principal has `groups`, `scopes` and `roles`, which are empty for most of them.
It also keeps 14 digits, so `0.30000000000000004` came back as `0.3`. A script that rewrites
identity data to change a flag is the wrong tool.

I did not use a key for each field either. Four keys expire separately, and a taint that lives in
its own key can outlive the session or vanish while the session is in use. One key has one life.

Reading with `WATCH` and writing back would work, and a counter would then cost a retry loop
where Redis has an increment.

**The durable row follows.** The `sessions` row (`final_flags`, `tainted`, `last_seen_at`) is
written with SQL that merges: the flags are a union, `tainted = tainted OR new`, and
`last_seen_at = GREATEST(...)`. Two writers in any order leave the same row, and a writer that
knows less changes nothing. A flag or a taint that is new goes to the row at once, within 2
seconds, because nothing else would carry it there if the session ended soon after. `save` and
`touch` write the row at most once a minute, as `save` did before. A Postgres failure is logged
and the call goes on; the next write brings the row up to date.

**Callers.**

- The gateway no longer saves the session when a call ends. It calls `touch`. The copy a call
  read at its start is never written back.
- A slot that learns something records it with the store's methods as soon as it knows, then
  brings the call's own copy up to date with `catch_up(ctx.session, returned)`. A slot that only
  changes `ctx.session` records nothing, because nobody writes that copy back. A request with no
  session id has a throwaway state that is never stored: the methods return `None` for it, and
  the slot changes the call's copy alone.
- A call that was approved after a wait reads its session again before the slots ahead of the
  approval run a second time (`Pipeline.run_before`, ADR-0010). The policy then decides on the
  taint as it is when the call is dispatched, and not on the copy from before the wait.
  `PipelineDeps.sessions` is how the pipeline reaches the store.
- `InMemorySessionStore` hands out copies, as Redis does, so a test of a merge there tests the
  same thing. Both stores run the same contract (`tests/fixtures/session_contract.py`).

## Consequences

- The plan's data model (section 3.7) calls `ks:sess:{session_id}` a JSON `SessionState`. It is a
  hash now. `docs/runbook.md` describes it.
- A key in the old format, a JSON string, cannot be read. `get`, `peek` and the listing treat it
  as a session they have not seen and `create` replaces it. There is no migration: a session
  lives 24 hours at most, and the gateway serves only sessions it opened itself (the binding of
  a session to its principal is kept in the process), so nothing asks for a key from before the
  upgrade again.
- Merges do not make calls wait for each other. Two calls of a session still run at once, and
  each decides on the state it read. A taint recorded while another call is in flight reaches
  that call only if it waits for approval, or at its next read. The Rule of Two policies decide
  at the start of a call, so a call already past the policy slot when the taint lands is not
  stopped by it.
- Nothing clears a taint while the session lives. To clear one, delete the key in Redis: the next
  call of that MCP session starts a clean state. That access is outside what the gateway defends.
- A counter does not go down. A refund is a ledger entry (Phase 8), not a lower number in the
  session.
- A flag that a newer version writes and this one does not know is left out of the copy that
  `get` returns. It is not a reason to lose the session.
- It costs a little. On this machine against Redis in Docker, the median read of a session went
  from 0.23 ms to 0.34 ms and the write at the end of a call from 0.24 ms to 0.29 ms (4000 runs
  after a warm-up, three repeats). A change that adds a flag, a count or spend is one more command
  of about 0.3 ms. KS-903 measures a whole call.

## Revisit when

A flag needs to say who set it and when, or an operator needs to clear a taint through the admin
API. Either belongs in fields of its own. The rule that a save cannot remove would stay.
