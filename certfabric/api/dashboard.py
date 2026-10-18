"""Numbers for the dashboard's global health ribbon."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from certfabric import app_settings
from certfabric.api.deps import get_db
from certfabric.models import Certificate, Device

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class Summary(BaseModel):
    server_time: datetime  # the UI computes "days left" from this, not the browser's clock
    active_certificates: int
    devices_monitored: int
    drift_alerts: int
    expiring_devices: int
    renewal_threshold_days: int
    next_sweep_at: datetime | None
    next_renewal_check_at: datetime | None


@router.get("/summary")
async def summary(request: Request, db: AsyncSession = Depends(get_db)) -> Summary:
    state = request.app.state
    now = state.clock.now()
    threshold = (await app_settings.load(db)).renewal_threshold_days
    devices = list(await db.scalars(select(Device)))
    due_times = [
        d.last_scanned_at + timedelta(minutes=d.polling_interval_minutes) if d.last_scanned_at else now
        for d in devices
    ]
    return Summary(
        server_time=now,
        active_certificates=await db.scalar(
            select(func.count()).select_from(Certificate).where(Certificate.status == "VALID", Certificate.expires_at > now)
        )
        or 0,
        devices_monitored=len(devices),
        drift_alerts=sum(d.drift_status == "DRIFT_DETECTED" for d in devices),
        expiring_devices=sum(
            1 for d in devices if d.presented_expires_at and d.presented_expires_at - now <= timedelta(days=threshold)
        ),
        renewal_threshold_days=threshold,
        next_sweep_at=max(min(due_times), now) if due_times else None,
        next_renewal_check_at=state.scheduler.next_run("renewal-check"),
    )
