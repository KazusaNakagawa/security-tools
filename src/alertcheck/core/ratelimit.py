"""Per-host request spacing and concurrency cap (spec §6.1)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager


class HostRateLimiter:
    """Spaces requests to the same host at least ``1 / rps`` seconds apart.

    The next slot is reserved synchronously before sleeping, so concurrent
    callers on one event loop never share a slot. Idle time does not build up
    a burst allowance.
    """

    def __init__(
        self,
        rps: float,
        concurrency: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if rps <= 0:
            raise ValueError("rps must be positive")
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        self._interval = 1.0 / rps
        self._concurrency = concurrency
        self._clock = clock
        self._sleep = sleep
        self._next: dict[str, float] = {}
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    def _semaphore(self, host: str) -> asyncio.Semaphore:
        if host not in self._semaphores:
            self._semaphores[host] = asyncio.Semaphore(self._concurrency)
        return self._semaphores[host]

    @asynccontextmanager
    async def slot(self, host: str) -> AsyncIterator[None]:
        async with self._semaphore(host):
            now = self._clock()
            start = max(now, self._next.get(host, now))
            self._next[host] = start + self._interval
            if start > now:
                await self._sleep(start - now)
            yield
