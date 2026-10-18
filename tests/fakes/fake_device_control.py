"""Shared state between tests and the `fake_device` Plugin (which is loaded from disk).

Tests register a FakeTlsDevice under its port and choose how the Plugin behaves for it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tests.fakes.tls_device import FakeTlsDevice


@dataclass
class Control:
    device: FakeTlsDevice
    # succeed: install the cert; fail: return False; raise: PluginError; no_effect: claim success, change nothing
    mode: str = "succeed"
    delay: float = 0.0
    bad_credentials: bool = False
    deploys: int = 0
    calls: list[str] = field(default_factory=list)


CONTROLS: dict[int, Control] = {}


def register(device: FakeTlsDevice) -> Control:
    CONTROLS[device.port] = Control(device)
    return CONTROLS[device.port]
