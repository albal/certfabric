"""Time source. Everything that depends on "now" reads it from a Clock so tests can move time."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FakeClock:
    """A clock that only moves when told to. Use `Scheduler.advance` to run jobs along the way."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 1, 1, tzinfo=UTC)
        # Called with the new time whenever it moves, so out-of-process fakes can follow.
        self.listeners: list[Callable[[datetime], None]] = []

    def now(self) -> datetime:
        return self._now

    def set(self, value: datetime) -> None:
        if value < self._now:
            raise ValueError("FakeClock cannot move backwards")
        self._now = value
        for listener in self.listeners:
            listener(value)

    def advance(self, delta: timedelta) -> None:
        self.set(self._now + delta)
