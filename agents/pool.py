"""Bounded worker-pool helper for per-unit/per-batch stages; imposes no stage-wide
timeout, so callers keep their own per-task fallbacks."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager


@contextmanager
def worker_pool(workers: int):
    """Yield a bounded executor that never blocks teardown on orphaned work."""
    ex = ThreadPoolExecutor(max_workers=max(1, int(workers)))
    try:
        yield ex
    finally:
        try:
            ex.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
