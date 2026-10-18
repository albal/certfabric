"""Renewal is decided per Certificate, from its own expiry, never by Device Probes (ADR-0003)."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import select, update
from starlette.datastructures import State

from certfabric import app_settings, certificates
from certfabric.deployments import DeploymentRefused, auto_deploy_blocked
from certfabric.jobs import Job, JobFailed
from certfabric.models import Certificate, Device

log = logging.getLogger(__name__)

RENEWAL_CHECK_INTERVAL = timedelta(hours=1)
RENEWAL_RETRY_AFTER = timedelta(hours=6)
SUPERSEDED_KEY_RETENTION = timedelta(days=30)


class Renewer:
    def __init__(self, state: State) -> None:
        self._state = state
        self._renewing: set[str] = set()

    async def check(self) -> None:
        """Scheduled job: renew Certificates inside the threshold, and expire old keys."""
        state = self._state
        now = state.clock.now()
        async with state.db.session() as db:
            threshold = timedelta(days=(await app_settings.load(db)).renewal_threshold_days)
            due = list(
                await db.scalars(
                    select(Certificate).where(Certificate.status == "VALID", Certificate.expires_at <= now + threshold)
                )
            )
        for cert in due:
            recently_failed = cert.renewal_error and cert.renewal_attempted_at and (
                now - cert.renewal_attempted_at < RENEWAL_RETRY_AFTER
            )
            if cert.id not in self._renewing and not recently_failed:
                self.start(cert.id)
        await self._delete_superseded_keys()

    def start(self, cert_id: str) -> Job:
        self._renewing.add(cert_id)

        async def run(job: Job) -> dict[str, Any]:
            try:
                return await self._renew(job, cert_id)
            finally:
                self._renewing.discard(cert_id)

        return self._state.jobs.start("renewal", run)

    async def _renew(self, job: Job, old_id: str) -> dict[str, Any]:
        state = self._state
        async with state.db.session() as db:
            old = await db.get(Certificate, old_id)
        if old is None or old.status != "VALID":
            return {}
        job.write(f"Renewing Certificate {old.id} ({old.domain_primary}), expires {old.expires_at:%Y-%m-%d}")
        try:
            new = await certificates.obtain(
                state, job, domains=old.san_list, dns_provider_id=old.dns_provider_id, key_type=old.key_type
            )
        except JobFailed as exc:
            await self._failed(old, str(exc))
            raise

        now = state.clock.now()
        async with state.db.session() as db, db.begin():
            db.add(new)
            stored = await db.get(Certificate, old.id)
            stored.status = "SUPERSEDED"
            stored.superseded_by = new.id
            stored.superseded_at = now
            stored.renewal_attempted_at = now
            stored.renewal_error = None
            await db.execute(update(Device).where(Device.assigned_cert_id == old.id).values(assigned_cert_id=new.id))
            devices = list(await db.scalars(select(Device).where(Device.assigned_cert_id == new.id)))
        job.write(f"Stored Certificate {new.id}; deploying to {len(devices)} Device(s)")

        for device in devices:
            if auto_deploy_blocked(device, now) or state.deployer.is_running(device.id):
                job.write(f"Not deploying to {device.name} now; it will be healed as Outdated")
                continue
            try:
                await state.deployer.start(device.id, "RENEWAL")
            except DeploymentRefused as exc:
                job.write(f"Not deploying to {device.name}: {exc}")
        return {"certificate_id": new.id, "replaces": old.id}

    async def _failed(self, old: Certificate, error: str) -> None:
        state = self._state
        async with state.db.session() as db, db.begin():
            stored = await db.get(Certificate, old.id)
            if stored is None:
                return
            stored.renewal_attempted_at = state.clock.now()
            stored.renewal_error = error
        await state.notifier.emit(
            "renewal_failed",
            f"Renewing {old.domain_primary} failed: {error}. Retrying in {RENEWAL_RETRY_AFTER.total_seconds() / 3600:g}h",
            certificate=old,
            level="error",
        )

    async def _delete_superseded_keys(self) -> None:
        cutoff = self._state.clock.now() - SUPERSEDED_KEY_RETENTION
        async with self._state.db.session() as db, db.begin():
            await db.execute(
                update(Certificate)
                .where(
                    Certificate.status == "SUPERSEDED",
                    Certificate.superseded_at <= cutoff,
                    Certificate.privkey_pem_encrypted.is_not(None),
                )
                .values(privkey_pem_encrypted=None)
            )
