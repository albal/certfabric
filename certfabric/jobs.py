"""Long-running jobs (issuance, Deployment) whose redacted output can be followed live."""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from certfabric.redaction import Redactor

log = logging.getLogger(__name__)

JobState = Literal["running", "succeeded", "failed"]


class JobFailed(Exception):
    """Raised inside a job to fail it with a message meant for the admin."""


@dataclass
class Job:
    id: str
    kind: str
    redactor: Redactor = field(default_factory=Redactor)
    state: JobState = "running"
    lines: list[str] = field(default_factory=list)
    error: str | None = None
    result: dict[str, Any] = field(default_factory=dict)
    _listeners: set[asyncio.Queue[str | None]] = field(default_factory=set)
    _done: asyncio.Event = field(default_factory=asyncio.Event)

    def write(self, text: str) -> None:
        for raw in text.splitlines():
            line = self.redactor.redact_line(raw)
            if line is None:
                continue
            self.lines.append(line)
            for queue in self._listeners:
                queue.put_nowait(line)

    def output(self) -> str:
        return "\n".join(self.lines)

    def _finish(self, state: JobState, error: str | None = None) -> None:
        self.state = state
        self.error = self.redactor.redact(error) if error else None
        self._done.set()
        for queue in self._listeners:
            queue.put_nowait(None)

    async def wait(self) -> None:
        await self._done.wait()

    async def follow(self) -> AsyncIterator[str]:
        """Yield every line written so far, then new lines until the job finishes."""
        queue: asyncio.Queue[str | None] = asyncio.Queue()
        backlog = list(self.lines)
        running = self.state == "running"
        if running:
            self._listeners.add(queue)
        try:
            for line in backlog:
                yield line
            if not running:
                return
            while (line := await queue.get()) is not None:
                yield line
        finally:
            self._listeners.discard(queue)


JobFn = Callable[[Job], Awaitable[dict[str, Any] | None]]


class JobRegistry:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._tasks: set[asyncio.Task[None]] = set()

    def start(self, kind: str, fn: JobFn, redactor: Redactor | None = None) -> Job:
        job = Job(id=uuid.uuid4().hex, kind=kind, redactor=redactor or Redactor())
        self._jobs[job.id] = job
        task = asyncio.create_task(self._run(job, fn))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return job

    async def _run(self, job: Job, fn: JobFn) -> None:
        try:
            job.result = await fn(job) or {}
        except JobFailed as exc:
            job._finish("failed", str(exc))
        except Exception as exc:
            log.exception("Job %s (%s) crashed", job.id, job.kind)
            job._finish("failed", f"Internal error: {exc}")
        else:
            job._finish("succeeded")

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
