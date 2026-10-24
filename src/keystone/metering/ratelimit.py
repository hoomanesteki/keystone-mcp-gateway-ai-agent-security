"""Token buckets in Redis (KS-804).

A bucket holds up to `capacity` tokens and gets `refill_per_s` back every second. A call takes one
token. A bucket that is empty refuses the call and says how long it is until it has a token again.

The sums are `step`, a plain function, so that they are tested without Redis and the Lua script
can be tested against them. The script does the same sums inside Redis in one step, for every
bucket a call is checked against: it asks each in turn, and only when all of them have a token does
it take one from each. A call refused by the third bucket has not used a token of the first two.

`now` is an argument and not the clock of Redis. That is what lets a test hold the time still, and
it means that two Keystone processes whose clocks differ by a little disagree by a little. A bucket
never gives tokens back for time that ran backwards, and keeps the later of two moments.

A bucket nobody has asked about for as long as it takes to fill from empty is full, and a full
bucket is the same as one that was never made. The key expires after that, so an idle user costs
Redis nothing.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import NamedTuple, Protocol

from redis.asyncio import Redis

KEY_PREFIX = "ks:rl:"
# The most buckets the in-memory limiter keeps. A process with no Redis serves one deployment, and
# this is far above the users it can have; past it the least recently used goes, which gives its
# user a full bucket back, the failure that costs the least.
MAX_MEMORY_BUCKETS = 100_000
SWEEP_EVERY_S = 60.0


class Step(NamedTuple):
    """What one asking of one bucket came to. `held` and `stamp` are what to store: for a refusal
    they are the bucket as it was after the refill, and nothing was taken."""

    allowed: bool
    held: float
    stamp: float
    retry_after_s: float


def step(
    held: float | None,
    stamp: float | None,
    now: float,
    capacity: float,
    refill_per_s: float,
    cost: float = 1.0,
) -> Step:
    """Ask a bucket for `cost` tokens at `now`. A bucket that is not there yet (`held` is None) is
    full. The refill is for the time since `stamp`, up to the capacity; time that went backwards
    gives nothing and moves nothing. A capacity that was lowered since cuts what is held."""
    if held is None or stamp is None:
        held, stamp = capacity, now
    if now > stamp:
        held = min(capacity, held + (now - stamp) * refill_per_s)
        stamp = now
    held = min(held, capacity)
    if held < cost:
        return Step(False, held, stamp, (cost - held) / refill_per_s)
    return Step(True, held - cost, stamp, 0.0)


@dataclass(frozen=True)
class Bucket:
    """One bucket a call is asked against: the scope it belongs to (`per_user`, for the log and the
    metric), the key it is stored under, and its size."""

    scope: str
    key: str
    capacity: float
    refill_per_s: float


@dataclass(frozen=True)
class Verdict:
    """The answer. When `allowed` is false, `scope` is the first bucket that had no token and
    `retry_after_s` is the seconds until it has one."""

    allowed: bool
    scope: str | None = None
    retry_after_s: float = 0.0


ALLOWED = Verdict(allowed=True)


class RateLimiter(Protocol):
    async def check(self, buckets: Sequence[Bucket], now: float) -> Verdict:
        """Take one token from each bucket, or take none and say which bucket refused."""
        ...


class MemoryLimiter:
    """The same buckets in this process, for a Keystone with no Redis (one process, state lost on
    restart) and for tests. Nothing awaits between reading a bucket and writing it, so a check is
    atomic for the event loop."""

    def __init__(self, max_buckets: int = MAX_MEMORY_BUCKETS) -> None:
        self._max = max_buckets
        # key -> (held, stamp, when it is full again)
        self._state: OrderedDict[str, tuple[float, float, float]] = OrderedDict()
        self._swept_at = 0.0

    @property
    def size(self) -> int:
        return len(self._state)

    async def check(self, buckets: Sequence[Bucket], now: float) -> Verdict:
        taken: list[tuple[Bucket, Step]] = []
        for bucket in buckets:
            stored = self._state.get(bucket.key)
            answer = step(
                stored[0] if stored else None,
                stored[1] if stored else None,
                now,
                bucket.capacity,
                bucket.refill_per_s,
            )
            if not answer.allowed:
                return Verdict(False, bucket.scope, answer.retry_after_s)
            taken.append((bucket, answer))
        for bucket, answer in taken:
            full_at = answer.stamp + (bucket.capacity - answer.held) / bucket.refill_per_s
            self._state[bucket.key] = (answer.held, answer.stamp, full_at)
            self._state.move_to_end(bucket.key)
        self._sweep(now)
        return ALLOWED

    def _sweep(self, now: float) -> None:
        if now - self._swept_at >= SWEEP_EVERY_S:
            self._swept_at = now
            for key in [k for k, (_, _, full_at) in self._state.items() if full_at <= now]:
                del self._state[key]
        while len(self._state) > self._max:
            self._state.popitem(last=False)


# KEYS: the buckets, in the order they are asked. ARGV[1] is `now` in seconds; after it come each
# bucket's capacity and refill rate. Returns {1, 0, '0'} when every bucket had a token and each gave
# one, and {0, i, retry} when bucket i had none: nothing was taken from any bucket, and `retry` is
# the seconds until bucket i has one. It is text because a Lua number is cut to an integer when it
# leaves the script. The sums are those of `step`.
SCRIPT = """
local now = tonumber(ARGV[1])
local count = #KEYS
local held = {}
local stamps = {}
for i = 1, count do
  local capacity = tonumber(ARGV[2 * i])
  local rate = tonumber(ARGV[2 * i + 1])
  local state = redis.call('HMGET', KEYS[i], 'tokens', 'ts')
  local tokens = tonumber(state[1])
  local stamp = tonumber(state[2])
  if tokens == nil or stamp == nil then
    tokens = capacity
    stamp = now
  end
  if now > stamp then
    tokens = math.min(capacity, tokens + (now - stamp) * rate)
    stamp = now
  end
  tokens = math.min(tokens, capacity)
  if tokens < 1 then
    return {0, i, tostring((1 - tokens) / rate)}
  end
  held[i] = tokens - 1
  stamps[i] = stamp
end
for i = 1, count do
  local capacity = tonumber(ARGV[2 * i])
  local rate = tonumber(ARGV[2 * i + 1])
  redis.call('HSET', KEYS[i], 'tokens', string.format('%.9f', held[i]),
             'ts', string.format('%.6f', stamps[i]))
  redis.call('PEXPIRE', KEYS[i], math.ceil(capacity / rate * 1000) + 1000)
end
return {1, 0, '0'}
"""


def _text(value: str | bytes) -> str:
    return value.decode() if isinstance(value, bytes) else value


class RedisLimiter:
    """Buckets as hashes under `ks:rl:...` (plan section 3.7), checked by one script, so that
    several processes share them and a check is atomic."""

    def __init__(self, redis: Redis) -> None:
        self._script = redis.register_script(SCRIPT)

    async def check(self, buckets: Sequence[Bucket], now: float) -> Verdict:
        if not buckets:
            return ALLOWED
        arguments: list[str] = [f"{now:.6f}"]
        for bucket in buckets:
            arguments += [repr(float(bucket.capacity)), repr(float(bucket.refill_per_s))]
        reply = await self._script(keys=[b.key for b in buckets], args=arguments)
        allowed, index, retry = reply
        if int(allowed) == 1:
            return ALLOWED
        refused = buckets[int(index) - 1]
        return Verdict(False, refused.scope, float(_text(retry)))


def whole_milliseconds(seconds: float) -> float:
    """A wait rounded up to the millisecond and never zero, so that a client that waits this long
    is not refused again for a fraction of one."""
    return max(1, math.ceil(seconds * 1000)) / 1000
