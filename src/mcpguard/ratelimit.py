"""Per-tool token-bucket rate limiting with an injectable clock (so tests need no sleeping)."""

from __future__ import annotations

import time
from collections.abc import Callable


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_refill)

    def allow(self, key: str, per_minute: int) -> bool:
        now = self._clock()
        capacity = float(per_minute)
        tokens, last = self._buckets.get(key, (capacity, now))
        tokens = min(capacity, tokens + (now - last) * per_minute / 60.0)
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            return True
        self._buckets[key] = (tokens, now)
        return False
