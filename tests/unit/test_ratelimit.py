import asyncio

import pytest

from alertcheck.core.ratelimit import HostRateLimiter


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class TestHostRateLimiter:
    async def test_first_request_does_not_wait(self):
        clock = FakeClock()
        limiter = HostRateLimiter(rps=5, concurrency=4, clock=clock.time, sleep=clock.sleep)
        async with limiter.slot("a.example"):
            pass
        assert clock.sleeps == []

    async def test_burst_is_spaced_by_rps(self):
        clock = FakeClock()
        limiter = HostRateLimiter(rps=5, concurrency=4, clock=clock.time, sleep=clock.sleep)
        for _ in range(3):
            async with limiter.slot("a.example"):
                pass
        assert clock.now == pytest.approx(0.4)

    async def test_hosts_are_limited_independently(self):
        clock = FakeClock()
        limiter = HostRateLimiter(rps=1, concurrency=4, clock=clock.time, sleep=clock.sleep)
        async with limiter.slot("a.example"):
            pass
        async with limiter.slot("b.example"):
            pass
        assert clock.sleeps == []

    async def test_idle_time_does_not_accumulate_burst(self):
        clock = FakeClock()
        limiter = HostRateLimiter(rps=2, concurrency=4, clock=clock.time, sleep=clock.sleep)
        async with limiter.slot("a"):
            pass
        clock.now += 10
        async with limiter.slot("a"):
            pass
        async with limiter.slot("a"):
            pass
        assert clock.sleeps == [pytest.approx(0.5)]

    async def test_concurrency_is_capped_per_host(self):
        limiter = HostRateLimiter(rps=1000, concurrency=2)
        active = 0
        peak = 0

        async def worker():
            nonlocal active, peak
            async with limiter.slot("a"):
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.01)
                active -= 1

        await asyncio.gather(*(worker() for _ in range(6)))
        assert peak == 2

    @pytest.mark.parametrize("rps,concurrency", [(0, 1), (-1, 1), (1, 0)])
    def test_invalid_parameters(self, rps, concurrency):
        with pytest.raises(ValueError):
            HostRateLimiter(rps=rps, concurrency=concurrency)
