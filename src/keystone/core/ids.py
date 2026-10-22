"""ULIDs for call ids: 48 bits of millisecond time, then 80 random bits, in Crockford base32."""

from __future__ import annotations

import secrets
import threading
import time

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_RANDOM_BITS = 80
_lock = threading.Lock()
_last_ms = -1
_last_random = 0


def _encode(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def new_id() -> str:
    """A new ULID. Ids from one process sort in creation order, even within one millisecond."""
    global _last_ms, _last_random
    now_ms = time.time_ns() // 1_000_000
    with _lock:
        if now_ms > _last_ms:
            _last_ms, _last_random = now_ms, secrets.randbits(_RANDOM_BITS)
        else:
            # Same millisecond, or the clock stepped back: keep order by counting up.
            _last_random += 1
            if _last_random >> _RANDOM_BITS:
                _last_ms, _last_random = _last_ms + 1, secrets.randbits(_RANDOM_BITS)
        ms, rand = _last_ms, _last_random
    return _encode(ms, 10) + _encode(rand, 16)
