"""The Deployment engine: one Plugin Deployment per Device at a time, verified and logged."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from starlette.datastructures import State

from certfabric.jobs import Job, JobFailed
from certfabric.models import Certificate, DeploymentLog, Device
from certfabric.plugins.base import DeviceCredentials, PluginError, generate_passphrase
from certfabric.redaction import Redactor
from certfabric.x509util import build_pkcs12, info_from_pem, split_pem_chain


log = logging.getLogger(__name__)

# Wait before each automatic retry after a failure; the last value repeats (the cap).
RETRY_BACKOFF = (timedelta(hours=1), timedelta(hours=6), timedelta(hours=24))
DEPLOY_FAILED_AFTER = 3
RETRY_SWEEP_INTERVAL = timedelta(minutes=1)


def auto_deploy_blocked(device: Device, now: datetime) -> bool:
    """Automatic Deployments wait out the backoff, and stop entirely once Deploy Failed."""
    if device.consecutive_deploy_failures >= DEPLOY_FAILED_AFTER:
        return True
    return device.next_retry_at is not None and now < device.next_retry_at


class DeploymentRefused(Exception):
    """The Deployment cannot start; the message says why."""


class DeploymentInProgress(DeploymentRefused):
    pass


class Deployer:
    def __init__(self, state: State) -> None:
        self._state = state
        # Device ids with a Deployment running. Checked and set without awaiting, so on one
        # event loop this is the per-Device lock.
        self._running: set[str] = set()

    def is_running(self, device_id: str) -> bool:
        return device_id in self._running

    async def start(self, device_id: str, trigger_source: str) -> Job:
        """Start a Deployment of the Device's assigned Certificate. Raises DeploymentRefused."""
        if device_id in self._running:
            raise DeploymentInProgress("A Deployment is already running for this Device")
        self._running.add(device_id)
        try:
            async with self._state.db.session() as db:
                device = await db.get(Device, device_id)
                if device is None:
                    raise DeploymentRefused("Device not found")
                if device.assigned_cert_id is None:
                    raise DeploymentRefused("Device is Monitor-only: assign a Certificate first")
                if self._state.plugins.get(device.plugin_id) is None:
                    raise DeploymentRefused(f"Plugin {device.plugin_id!r} is not installed")
                # Callers decide from reads taken before a Deployment that just finished may have
                # pushed the backoff out; re-check under the lock.
                if trigger_source != "MANUAL" and auto_deploy_blocked(device, self._state.clock.now()):
                    raise DeploymentRefused("Waiting out the backoff after a failed Deployment")
            if trigger_source == "MANUAL":
                await self._reset_failures(device_id)
        except BaseException:
            self._running.discard(device_id)
            raise

        async def run(job: Job) -> dict[str, Any]:
            try:
                result = await self._deploy(job, device_id, trigger_source)
            finally:
                self._running.discard(device_id)
            await self._catch_up(job, device_id, result["certificate_id"])
            return result

        return self._state.jobs.start("deployment", run)

    async def _catch_up(self, job: Job, device_id: str, deployed_cert_id: str) -> None:
        """If a renewal reassigned the Device while this Deployment ran, deploy the new one too."""
        async with self._state.db.session() as db:
            device = await db.get(Device, device_id)
        if device is None or device.assigned_cert_id in (None, deployed_cert_id):
            return
        job.write("The assigned Certificate changed during this Deployment; deploying the new one")
        try:
            await self.start(device_id, "RENEWAL")
        except DeploymentRefused as exc:
            log.info("Could not catch up %s: %s", device_id, exc)

    async def _reset_failures(self, device_id: str) -> None:
        """Someone intervened: forget past failures so automatic healing can resume."""
        async with self._state.db.session() as db, db.begin():
            device = await db.get(Device, device_id)
            if device is not None:
                reset_failures(device)

    async def retry_due(self) -> None:
        """Retry Devices whose backoff has elapsed (scheduled job)."""
        now = self._state.clock.now()
        async with self._state.db.session() as db:
            due = list(
                await db.scalars(
                    select(Device.id).where(
                        Device.next_retry_at.is_not(None),
                        Device.next_retry_at <= now,
                        Device.consecutive_deploy_failures < DEPLOY_FAILED_AFTER,
                        Device.assigned_cert_id.is_not(None),
                    )
                )
            )
        for device_id in due:
            if not self.is_running(device_id):
                try:
                    await self.start(device_id, "RETRY")
                except DeploymentRefused as exc:
                    log.info("Not retrying %s: %s", device_id, exc)

    async def _deploy(self, job: Job, device_id: str, trigger_source: str) -> dict[str, Any]:
        state = self._state
        async with state.db.session() as db:
            device = await db.get(Device, device_id)
            cert = await db.get(Certificate, device.assigned_cert_id) if device else None
        if device is None or cert is None or not cert.privkey_pem_encrypted:
            raise JobFailed("Device or its Certificate disappeared before the Deployment started")

        creds = DeviceCredentials(**state.vault.decrypt_json(device.encrypted_credentials or "{}"))
        key_pem = state.vault.decrypt(cert.privkey_pem_encrypted)
        plugin_cls = state.plugins.get(device.plugin_id)
        # A fresh passphrase per Deployment, never stored, unless the Device needs a fixed one.
        passphrase = creds.pfx_passphrase or generate_passphrase(plugin_cls.pfx_passphrase_max_length)
        job.redactor.add([*creds.secrets(), passphrase])
        limit = plugin_cls.pfx_passphrase_max_length
        if limit and len(passphrase) > limit:
            raise JobFailed(f"The Device's fixed PKCS#12 passphrase is longer than the {limit} characters it accepts")
        chain = split_pem_chain(cert.fullchain_pem)[1:] if plugin_cls.pfx_include_chain else []
        pfx = build_pkcs12(cert.cert_pem, key_pem, passphrase, chain)
        plugin = plugin_cls(
            device.hostname, device.port, creds, options=device.plugin_options, sni=device.sni, log=job.write
        )

        job.write(f"Deploying Certificate {cert.id} ({cert.domain_primary}) to {device.name} via {plugin_cls.plugin_id}")
        started = time.monotonic()
        error: str | None = None
        try:
            if not await plugin.deploy_certificate(cert.cert_pem, key_pem, cert.fullchain_pem, pfx, passphrase):
                error = "Plugin reported the Deployment failed"
            elif not await plugin.post_deployment_verify(cert.fingerprint_sha256):
                error = "Verification failed: the Device is not serving the new Certificate"
        except PluginError as exc:
            error = str(exc)
        except Exception as exc:
            error = f"Plugin crashed: {type(exc).__name__}: {exc}"
        elapsed_ms = int((time.monotonic() - started) * 1000)
        job.write(f"Deployment {'failed: ' + error if error else 'verified'} ({elapsed_ms} ms)")

        await self._record(job, device_id, cert, trigger_source, error, elapsed_ms, job.redactor)
        if error:
            raise JobFailed(error)
        return {"device_id": device_id, "certificate_id": cert.id}

    async def _record(
        self,
        job: Job,
        device_id: str,
        cert: Certificate,
        trigger_source: str,
        error: str | None,
        elapsed_ms: int,
        redactor: Redactor,
    ) -> None:
        state = self._state
        now = state.clock.now()
        async with state.db.session() as db, db.begin():
            db.add(
                DeploymentLog(
                    id=uuid.uuid4().hex,
                    device_id=device_id,
                    cert_id=cert.id,
                    trigger_source=trigger_source,
                    success=error is None,
                    execution_time_ms=elapsed_ms,
                    log_output=redactor.redact(job.output()),
                    timestamp=now,
                )
            )
            device = await db.get(Device, device_id)
            if device is None:
                return
            gave_up = False
            if error is None:
                # Verification just saw the Device serve this Certificate.
                info = info_from_pem(cert.cert_pem)
                device.drift_status = "IN_SYNC"
                device.consecutive_deploy_failures = 0
                device.next_retry_at = None
                device.presented_fingerprint = info.fingerprint_sha256
                device.presented_issuer = info.issuer
                device.presented_common_name = info.common_name
                device.presented_sans = info.sans
                device.presented_serial = info.serial_number
                device.presented_expires_at = info.not_after
            else:
                device.consecutive_deploy_failures += 1
                if device.consecutive_deploy_failures >= DEPLOY_FAILED_AFTER:
                    device.drift_status = "DEPLOY_FAILED"
                    device.next_retry_at = None
                    gave_up = True
                else:
                    wait = RETRY_BACKOFF[min(device.consecutive_deploy_failures, len(RETRY_BACKOFF)) - 1]
                    device.next_retry_at = now + wait
        if gave_up:
            await state.notifier.emit(
                "deploy_failed",
                f"{device.name}: {DEPLOY_FAILED_AFTER} Deployments failed in a row ({error}); "
                "automatic retries stopped until you redeploy or fix its credentials",
                device=device,
                certificate=cert,
                level="error",
            )


def reset_failures(device: Device) -> None:
    device.consecutive_deploy_failures = 0
    device.next_retry_at = None
    if device.drift_status == "DEPLOY_FAILED":
        device.drift_status = "UNKNOWN"
