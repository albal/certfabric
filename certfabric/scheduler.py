"""A small interval scheduler driven by a Clock.

Jobs run when the clock passes their due time. In production `run_forever` polls the
system clock; in tests `advance` moves a FakeClock forward, stopping at each due time
so jobs see the time they were scheduled for.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from certfabric.clock import Clock, FakeClock

log = logging.getLogger(__name__)

JobFn = Callable[[], Awaitable[None]]


@dataclass
class Job:
    name: str
    interval: timedelta
    fn: JobFn
    next_run: datetime


class Scheduler:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._jobs: dict[str, Job] = {}

    def add_job(
        self, name: str, interval: timedelta, fn: JobFn, *, run_immediately: bool = False
    ) -> None:
        now = self._clock.now()
        self._jobs[name] = Job(name, interval, fn, now if run_immediately else now + interval)

    def remove_job(self, name: str) -> None:
        self._jobs.pop(name, None)

    def next_run(self, name: str) -> datetime | None:
        job = self._jobs.get(name)
        return job.next_run if job else None

    def next_due(self) -> datetime | None:
        return min((job.next_run for job in self._jobs.values()), default=None)

    async def run_due(self) -> None:
        now = self._clock.now()
        for job in sorted(self._jobs.values(), key=lambda j: j.next_run):
            if job.next_run > now:
                continue
            job.next_run = now + job.interval
            try:
                await job.fn()
            except Exception:
                log.exception("Scheduled job %s failed", job.name)

    async def advance(self, delta: timedelta) -> None:
        """Move a FakeClock forward by `delta`, running every job that falls due on the way."""
        if not isinstance(self._clock, FakeClock):
            raise TypeError("advance() needs a FakeClock")
        target = self._clock.now() + delta
        while (due := self.next_due()) is not None and due <= target:
            self._clock.set(max(due, self._clock.now()))
            await self.run_due()
        self._clock.set(target)

    async def run_forever(self, poll_seconds: float = 1.0) -> None:
        while True:
            await self.run_due()
            await asyncio.sleep(poll_seconds)
