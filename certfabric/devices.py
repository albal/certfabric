"""Probing Devices, classifying what they present, and healing them (ADR-0002)."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import State

from certfabric.deployments import DEPLOY_FAILED_AFTER, DeploymentRefused, auto_deploy_blocked
from certfabric.models import Certificate, DeploymentLog, Device
from certfabric.notifier import EventType, Level
from certfabric.probe import ProbeResult, probe

log = logging.getLogger(__name__)

SWEEP_INTERVAL = timedelta(minutes=1)
MAX_CONCURRENT_PROBES = 256
UNREACHABLE_AFTER_FAILURES = 3


@dataclass
class Notice:
    event: EventType
    message: str
    level: Level


@dataclass
class FollowUp:
    """Something to do once the Probe results are committed."""

    device: Device
    certificate: Certificate | None = None
    heal_trigger: str | None = None
    notices: list[Notice] = field(default_factory=list)


def is_due(device: Device, state: State) -> bool:
    if device.last_scanned_at is None:
        return True
    return state.clock.now() - device.last_scanned_at >= timedelta(minutes=device.polling_interval_minutes)


async def _previously_deployed(db: AsyncSession, device_id: str) -> set[str]:
    rows = await db.scalars(
        select(Certificate.fingerprint_sha256)
        .join(DeploymentLog, DeploymentLog.cert_id == Certificate.id)
        .where(DeploymentLog.device_id == device_id, DeploymentLog.success.is_(True))
    )
    return set(rows)


async def classify(db: AsyncSession, device: Device, assigned: Certificate) -> str:
    """IN_SYNC, OUTDATED (an earlier CertFabric Certificate) or DRIFT_DETECTED (anything else).

    A Device CertFabric has never deployed to stays UNKNOWN: its factory certificate is
    expected, not Drift, and it gets its first Deployment instead of an alarm.
    """
    if device.presented_fingerprint == assigned.fingerprint_sha256:
        return "IN_SYNC"
    deployed = await _previously_deployed(db, device.id)
    if not deployed:
        return "UNKNOWN"
    if device.presented_fingerprint in deployed:
        return "OUTDATED"
    return "DRIFT_DETECTED"


async def apply_probe(db: AsyncSession, device: Device, result: ProbeResult, state: State) -> FollowUp | None:
    """Record a Probe's outcome on the Device and classify it. Returns any follow-up action."""
    device.last_scanned_at = state.clock.now()
    if result.presented is None:
        device.consecutive_probe_failures += 1
        device.last_probe_error = result.error
        if device.consecutive_probe_failures == UNREACHABLE_AFTER_FAILURES:
            device.drift_status = "UNREACHABLE"
            message = f"{device.name} has failed {UNREACHABLE_AFTER_FAILURES} Probes in a row: {result.error}"
            return FollowUp(device=device, notices=[Notice("device_unreachable", message, "error")])
        return None
    notices: list[Notice] = []
    if device.drift_status == "UNREACHABLE":
        notices.append(Notice("device_recovered", f"{device.name} is reachable again", "info"))
        device.drift_status = "UNKNOWN"
    presented = result.presented
    device.consecutive_probe_failures = 0
    device.last_probe_error = None
    device.presented_fingerprint = presented.fingerprint_sha256
    device.presented_issuer = presented.issuer
    device.presented_common_name = presented.common_name
    device.presented_sans = presented.sans
    device.presented_serial = presented.serial_number
    device.presented_expires_at = presented.not_after

    assigned = await db.get(Certificate, device.assigned_cert_id) if device.assigned_cert_id else None
    if assigned is None:
        # Monitor-only: observed, never classified.
        return FollowUp(device=device, notices=notices) if notices else None
    previous = device.drift_status
    device.drift_status = await classify(db, device, assigned)
    if device.drift_status == "IN_SYNC":
        device.consecutive_deploy_failures = 0  # Healthy again, however it got there.
        device.next_retry_at = None
    elif device.consecutive_deploy_failures >= DEPLOY_FAILED_AFTER:
        device.drift_status = "DEPLOY_FAILED"  # Stays put until someone intervenes.
        return FollowUp(device=device, notices=notices) if notices else None
    if device.drift_status == "DRIFT_DETECTED" and previous != "DRIFT_DETECTED":
        notices.append(
            Notice(
                "drift_detected",
                f"{device.name} is serving a certificate CertFabric did not deploy "
                f"(fingerprint {device.presented_fingerprint}); redeploying",
                "warning",
            )
        )
    trigger = {"DRIFT_DETECTED": "DRIFT_HEAL", "OUTDATED": "OUTDATED_HEAL", "UNKNOWN": "INITIAL_SETUP"}.get(
        device.drift_status
    )
    if trigger and auto_deploy_blocked(device, state.clock.now()):
        trigger = None  # Backing off after a failure; the retry job picks it up.
    if trigger is None and not notices:
        return None
    return FollowUp(device=device, certificate=assigned, heal_trigger=trigger, notices=notices)


async def follow_up(state: State, actions: list[FollowUp]) -> None:
    for action in actions:
        for notice in action.notices:
            await state.notifier.emit(
                notice.event, notice.message, device=action.device, certificate=action.certificate, level=notice.level
            )
        if action.heal_trigger and not state.deployer.is_running(action.device.id):
            try:
                await state.deployer.start(action.device.id, action.heal_trigger)
            except DeploymentRefused as exc:
                log.info("Not healing %s: %s", action.device.name, exc)


async def probe_device(state: State, device_id: str) -> None:
    async with state.db.session() as db:
        device = await db.get(Device, device_id)
        if device is None:
            return
        host, port, sni = device.hostname, device.port, device.sni
    result = await probe(host, port, sni)
    async with state.db.session() as db, db.begin():
        device = await db.get(Device, device_id)
        action = await apply_probe(db, device, result, state) if device is not None else None
    await follow_up(state, [action] if action else [])


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
    actions: list[FollowUp] = []
    # One write transaction for the whole sweep keeps SQLite free of writer contention.
    async with state.db.session() as db, db.begin():
        for device_id, result in results:
            device = await db.get(Device, device_id)
            if device is not None and (action := await apply_probe(db, device, result, state)):
                actions.append(action)
    await follow_up(state, actions)
