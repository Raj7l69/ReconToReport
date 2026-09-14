"""
utils/rate_limiter.py
A thread-safe sliding-window rate limiter. Used to let NVD queries run
concurrently (via a thread pool) while still respecting NVD's published
rate limit — instead of the old approach of a blind time.sleep() between
every single sequential call, which serialized everything and made scans
with many services painfully slow.
"""

import threading
import time
from collections import deque


class RateLimiter:
    def __init__(self, max_calls: int, period_seconds: float):
        self.max_calls = max_calls
        self.period = period_seconds
        self._calls = deque()
        self._lock = threading.Lock()

    def acquire(self):
        """Block until a call is permitted under the sliding window, then record it."""
        while True:
            with self._lock:
                now = time.time()
                while self._calls and now - self._calls[0] > self.period:
                    self._calls.popleft()

                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return

                sleep_for = self.period - (now - self._calls[0]) + 0.05
            time.sleep(max(sleep_for, 0.05))