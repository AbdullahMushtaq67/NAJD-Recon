"""A small in-memory sliding-window rate limiter.

Good enough for a single-process deployment. For multiple workers you would back this with
Redis; the interface stays the same.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import Request


class RateLimiter:
    def __init__(self, max_events: int, window_seconds: int):
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> tuple[bool, int]:
        """Record an attempt. Returns (allowed, seconds_until_retry)."""
        now = time.monotonic()
        events = self._events[key]
        while events and now - events[0] >= self.window:
            events.popleft()
        if len(events) >= self.max_events:
            return False, int(self.window - (now - events[0])) + 1
        events.append(now)
        return True, 0


def client_key(request: Request, trust_proxy: bool) -> str:
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
