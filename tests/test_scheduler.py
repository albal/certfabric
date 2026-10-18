from datetime import timedelta

from certfabric.clock import FakeClock
from certfabric.scheduler import Scheduler


async def test_advancing_the_clock_runs_jobs_at_their_due_times():
    clock = FakeClock()
    start = clock.now()
    scheduler = Scheduler(clock)
    seen = []

    async def job():
        seen.append(clock.now() - start)

    scheduler.add_job("sweep", timedelta(hours=6), job)
    await scheduler.advance(timedelta(hours=5))
    assert seen == []
    await scheduler.advance(timedelta(hours=20))
    assert seen == [timedelta(hours=6), timedelta(hours=12), timedelta(hours=18), timedelta(hours=24)]
    assert clock.now() - start == timedelta(hours=25)


async def test_a_failing_job_does_not_stop_others():
    clock = FakeClock()
    scheduler = Scheduler(clock)
    ran = []

    async def boom():
        raise RuntimeError("nope")

    async def ok():
        ran.append(True)

    scheduler.add_job("boom", timedelta(minutes=1), boom)
    scheduler.add_job("ok", timedelta(minutes=1), ok)
    await scheduler.advance(timedelta(minutes=1))
    assert ran == [True]


async def test_app_scheduler_uses_the_harness_clock(scheduler, clock):
    ran = []

    async def job():
        ran.append(clock.now())

    scheduler.add_job("probe", timedelta(hours=6), job, run_immediately=True)
    await scheduler.advance(timedelta(hours=6))
    assert len(ran) == 2
