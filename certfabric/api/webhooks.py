"""Webhook URLs that receive event notifications."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import AnyHttpUrl, BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certfabric.api.deps import get_db
from certfabric.models import Webhook

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


class WebhookCreate(BaseModel):
    url: AnyHttpUrl


class WebhookOut(BaseModel):
    id: str
    url: str
    created_at: datetime


def _out(hook: Webhook) -> WebhookOut:
    return WebhookOut(id=hook.id, url=hook.url, created_at=hook.created_at)


@router.get("")
async def list_webhooks(db: AsyncSession = Depends(get_db)) -> list[WebhookOut]:
    return [_out(h) for h in await db.scalars(select(Webhook).order_by(Webhook.created_at))]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_webhook(body: WebhookCreate, request: Request, db: AsyncSession = Depends(get_db)) -> WebhookOut:
    hook = Webhook(id=uuid.uuid4().hex, url=str(body.url), created_at=request.app.state.clock.now())
    db.add(hook)
    await db.flush()
    return _out(hook)


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(webhook_id: str, db: AsyncSession = Depends(get_db)) -> None:
    hook = await db.get(Webhook, webhook_id)
    if hook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Webhook not found")
    await db.delete(hook)


@router.post("/test", status_code=status.HTTP_202_ACCEPTED)
async def send_test_event(request: Request) -> None:
    """Send a `test` event to every webhook."""
    await request.app.state.notifier.emit("test", "Test notification from CertFabric")
