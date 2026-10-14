"""One shared bounded worker-pool helper for per-unit/per-batch stages.

No stage-wide hard timeout is imposed by this helper: LangGraph runs are
bounded by ModelCallLimit middleware, the configured recursion limit, and
provider/model request timeouts. Callers keep their own per-task fallbacks.
"""
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
