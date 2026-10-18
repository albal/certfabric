"""Probing Devices and recording what they present."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from sqlalchemy import select
from starlette.datastructures import State

from certfabric.models import Device
from certfabric.probe import ProbeResult, probe

SWEEP_INTERVAL = timedelta(minutes=1)
MAX_CONCURRENT_PROBES = 256


def is_due(device: Device, state: State) -> bool:
    if device.last_scanned_at is None:
        return True
    return state.clock.now() - device.last_scanned_at >= timedelta(minutes=device.polling_interval_minutes)


def apply_probe(device: Device, result: ProbeResult, state: State) -> None:
    """Record a Probe's outcome on the Device."""
    device.last_scanned_at = state.clock.now()
    if result.presented is None:
        device.consecutive_probe_failures += 1
        device.last_probe_error = result.error
        return
    presented = result.presented
    device.consecutive_probe_failures = 0
    device.last_probe_error = None
    device.presented_fingerprint = presented.fingerprint_sha256
    device.presented_issuer = presented.issuer
    device.presented_common_name = presented.common_name
    device.presented_sans = presented.sans
    device.presented_serial = presented.serial_number
    device.presented_expires_at = presented.not_after


async def probe_device(state: State, device_id: str) -> None:
    async with state.db.session() as db:
        device = await db.get(Device, device_id)
        if device is None:
            return
        host, port, sni = device.hostname, device.port, device.sni
    result = await probe(host, port, sni)
    async with state.db.session() as db, db.begin():
        device = await db.get(Device, device_id)
        if device is not None:
            apply_probe(device, result, state)


async def sweep(state: State) -> None:
    """Probe every Device whose interval has elapsed, concurrently."""
    async with state.db.session() as db:
        devices = list(await db.scalars(select(Device)))
    due = [d for d in devices if is_due(d, state)]
    if not due:
        return
    limit = asyncio.Semaphore(MAX_CONCURRENT_PROBES)

    async def one(device: Device) -> tuple[str, ProbeResult]:
        async with limit:
            return device.id, await probe(device.hostname, device.port, device.sni)

    results = await asyncio.gather(*(one(d) for d in due))
    # One write transaction for the whole sweep keeps SQLite free of writer contention.
    async with state.db.session() as db, db.begin():
        for device_id, result in results:
            device = await db.get(Device, device_id)
            if device is not None:
                apply_probe(device, result, state)
