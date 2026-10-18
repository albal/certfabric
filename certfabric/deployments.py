"""The Deployment engine: one Plugin Deployment per Device at a time, verified and logged."""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Any

from starlette.datastructures import State

from certfabric.jobs import Job, JobFailed
from certfabric.models import Certificate, DeploymentLog, Device
from certfabric.plugins.base import DeviceCredentials, PluginError
from certfabric.redaction import Redactor
from certfabric.x509util import build_pkcs12, info_from_pem, split_pem_chain


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
        except BaseException:
            self._running.discard(device_id)
            raise

        async def run(job: Job) -> dict[str, Any]:
            try:
                return await self._deploy(job, device_id, trigger_source)
            finally:
                self._running.discard(device_id)

        return self._state.jobs.start("deployment", run)

    async def _deploy(self, job: Job, device_id: str, trigger_source: str) -> dict[str, Any]:
        state = self._state
        async with state.db.session() as db:
            device = await db.get(Device, device_id)
            cert = await db.get(Certificate, device.assigned_cert_id) if device else None
        if device is None or cert is None or not cert.privkey_pem_encrypted:
            raise JobFailed("Device or its Certificate disappeared before the Deployment started")

        creds = DeviceCredentials(**state.vault.decrypt_json(device.encrypted_credentials or "{}"))
        key_pem = state.vault.decrypt(cert.privkey_pem_encrypted)
        # A fresh passphrase per Deployment, never stored, unless the Device needs a fixed one.
        passphrase = creds.pfx_passphrase or secrets.token_urlsafe(18)
        job.redactor.add([*creds.secrets(), passphrase])
        plugin_cls = state.plugins.get(device.plugin_id)
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
