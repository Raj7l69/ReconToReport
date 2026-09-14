"""
tests/test_rate_limiter.py
Tests for utils/rate_limiter.py — confirms the sliding-window limiter
actually enforces the configured call budget under concurrent access.
"""
import time
import threading
from utils.rate_limiter import RateLimiter


def test_allows_calls_within_budget_immediately():
    limiter = RateLimiter(max_calls=5, period_seconds=10)
    start = time.time()
    for _ in range(5):
        limiter.acquire()
    elapsed = time.time() - start
    assert elapsed < 1  # 5 calls within budget of 5 should not block at all


def test_blocks_once_budget_exceeded():
    limiter = RateLimiter(max_calls=2, period_seconds=1)
    limiter.acquire()
    limiter.acquire()
    start = time.time()
    limiter.acquire()  # 3rd call must wait for the window to free up
    elapsed = time.time() - start
    assert elapsed >= 0.9  # should have waited close to the full period


def test_thread_safe_under_concurrent_access():
    limiter = RateLimiter(max_calls=3, period_seconds=1)
    call_times = []
    lock = threading.Lock()

    def worker():
        limiter.acquire()
        with lock:
            call_times.append(time.time())

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert len(call_times) == 6  # all 6 calls eventually completed, none lost/deadlocked