"""Test-side handle on the fake `acme.sh`: configure its behaviour, read its invocations."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from typing import Any

from certfabric.clock import FakeClock

FAKE_ACME = Path(__file__).with_name("fake_acme.py")


class FakeAcme:
    def __init__(self, directory: Path, clock: FakeClock) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.executable = directory / "acme.sh"
        self._control_path = directory / "control.json"
        self._invocations = directory / "invocations.jsonl"
        self._invocations.touch()
        self._clock = clock
        self._control: dict[str, Any] = {"invocations": str(self._invocations)}
        self.executable.write_text(
            f'#!/bin/sh\nFAKE_ACME_CONTROL="{self._control_path}" exec "{sys.executable}" "{FAKE_ACME}" "$@"\n'
        )
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        clock.listeners.append(lambda _now: self._write())
        self._write()

    def configure(self, **control: Any) -> None:
        """Options: fail, echo_env (list of variable names to print), print_key, validity_days."""
        self._control.update(control)
        self._write()

    def _write(self) -> None:
        self._control["now"] = self._clock.now().isoformat()
        self._control_path.write_text(json.dumps(self._control))

    @property
    def invocations(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self._invocations.read_text().splitlines()]
