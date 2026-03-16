from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class HostBudget:
    sem: asyncio.Semaphore
    blocked_until: float = 0.0


class PerHostLimiter:
    """
    Simple per-host concurrency limiter with block/cooldown support.

    This is not a token bucket; it is designed to prevent bursty behavior and
    to respect cooldown periods after rate-limit signals.
    """

    def __init__(self, per_host_max: int, global_rps: float = 0.0) -> None:
        self._per_host_max = per_host_max
        self._global_rps = global_rps
        self._budgets: Dict[str, HostBudget] = {}
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        budget = await self._get_budget(host)
        await self._sleep_if_blocked(budget)
        await budget.sem.acquire()

    async def release(self, host: str) -> None:
        budget = await self._get_budget(host)
        budget.sem.release()

    async def block(self, host: str, seconds: float) -> None:
        budget = await self._get_budget(host)
        budget.blocked_until = max(budget.blocked_until, time.time() + max(0.0, seconds))

    async def _get_budget(self, host: str) -> HostBudget:
        async with self._lock:
            b = self._budgets.get(host)
            
            # Handle global rate limiting
            if self._global_rps > 0:
                now = time.time()
                elapsed = now - self._last_request_time
                if elapsed < (1.0 / self._global_rps):
                    await asyncio.sleep((1.0 / self._global_rps) - elapsed)
                self._last_request_time = time.time()

            if b is None:
                b = HostBudget(sem=asyncio.Semaphore(self._per_host_max))
                self._budgets[host] = b
            return b

    async def _sleep_if_blocked(self, budget: HostBudget) -> None:
        now = time.time()
        if budget.blocked_until > now:
            await asyncio.sleep(budget.blocked_until - now)
