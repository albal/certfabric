"""The audit event feed shown on the dashboard."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certfabric.api.deps import get_db
from certfabric.models import AuditEvent

router = APIRouter(prefix="/api/events", tags=["events"])


class EventOut(BaseModel):
    id: str
    timestamp: datetime
    level: str
    event: str
    message: str
    device_id: str | None
    certificate_id: str | None


@router.get("")
async def list_events(
    limit: int = Query(default=100, ge=1, le=1000), db: AsyncSession = Depends(get_db)
) -> list[EventOut]:
    rows = await db.scalars(select(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(limit))
    return [
        EventOut(
            id=e.id,
            timestamp=e.timestamp,
            level=e.level,
            event=e.event,
            message=e.message,
            device_id=e.device_id,
            certificate_id=e.cert_id,
        )
        for e in rows
    ]
