"""Install-wide settings: CA choice, staging, renewal threshold."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from certfabric import app_settings
from certfabric.api.deps import get_db
from certfabric.app_settings import InstallSettings

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings(db: AsyncSession = Depends(get_db)) -> InstallSettings:
    return await app_settings.load(db)


@router.put("")
async def put_settings(body: InstallSettings, db: AsyncSession = Depends(get_db)) -> InstallSettings:
    await app_settings.save(db, body)
    return body
