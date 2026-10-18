"""Events: recorded for the dashboard and posted to every webhook as generic JSON.

Payloads are built from an allow-list of fields and never carry secrets.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Literal

import httpx
from sqlalchemy import select
from starlette.datastructures import State

from certfabric.models import AuditEvent, Certificate, Device, Webhook

log = logging.getLogger(__name__)

EventType = Literal[
    "drift_detected",
    "device_unreachable",
    "device_recovered",
    "deploy_failed",
    "renewal_failed",
    "test",
]
Level = Literal["info", "warning", "error"]
DELIVERY_TIMEOUT_SECONDS = 10.0


def device_summary(device: Device) -> dict[str, Any]:
    return {
        "id": device.id,
        "name": device.name,
        "hostname": device.hostname,
        "port": device.port,
        "plugin_id": device.plugin_id,
        "presented_fingerprint": device.presented_fingerprint,
    }


def certificate_summary(cert: Certificate) -> dict[str, Any]:
    return {
        "id": cert.id,
        "domain_primary": cert.domain_primary,
        "sans": cert.san_list,
        "fingerprint_sha256": cert.fingerprint_sha256,
        "expires_at": cert.expires_at.isoformat(),
    }


class Notifier:
    def __init__(self, state: State) -> None:
        self._state = state
        self._tasks: set[asyncio.Task[None]] = set()

    async def emit(
        self,
        event: EventType,
        message: str,
        *,
        device: Device | None = None,
        certificate: Certificate | None = None,
        level: Level = "info",
    ) -> None:
        """Record the event and queue its delivery to every webhook. Never waits for receivers."""
        now = self._state.clock.now()
        payload: dict[str, Any] = {
            "event": event,
            "level": level,
            "timestamp": now.isoformat(),
            "message": message,
            "device": device_summary(device) if device else None,
            "certificate": certificate_summary(certificate) if certificate else None,
        }
        async with self._state.db.session() as db, db.begin():
            if event != "test":
                db.add(
                    AuditEvent(
                        id=uuid.uuid4().hex,
                        timestamp=now,
                        level=level,
                        event=event,
                        message=message,
                        device_id=device.id if device else None,
                        cert_id=certificate.id if certificate else None,
                    )
                )
            urls = list(await db.scalars(select(Webhook.url)))
        for url in urls:
            task = asyncio.create_task(self._deliver(url, payload))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _deliver(self, url: str, payload: dict[str, Any]) -> None:
        try:
            async with httpx.AsyncClient(timeout=DELIVERY_TIMEOUT_SECONDS) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
        except Exception as exc:
            log.warning("Webhook delivery of %s to %s failed: %s", payload["event"], url, exc)

    async def drain(self) -> None:
        """Wait for deliveries in flight (used at shutdown and by tests)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
