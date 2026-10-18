"""Install-wide settings the admin changes at runtime, stored in the `settings` table."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certfabric.models import AppSetting


class InstallSettings(BaseModel):
    acme_ca: Literal["letsencrypt", "zerossl"] | str = Field(
        default="letsencrypt", description="letsencrypt, zerossl, or an https:// ACME directory URL"
    )
    acme_use_staging: bool = False
    renewal_threshold_days: int = Field(default=28, ge=1, le=89)

    @model_validator(mode="after")
    def _check(self) -> InstallSettings:
        if self.acme_ca not in ("letsencrypt", "zerossl") and not self.acme_ca.startswith("https://"):
            raise ValueError("acme_ca must be letsencrypt, zerossl, or an https:// URL")
        if self.acme_use_staging and self.acme_ca != "letsencrypt":
            raise ValueError("The staging CA option is only available for Let's Encrypt")
        return self

    def acme_server(self) -> str:
        if self.acme_ca == "letsencrypt":
            return "letsencrypt_test" if self.acme_use_staging else "letsencrypt"
        return self.acme_ca


async def load(db: AsyncSession) -> InstallSettings:
    rows = await db.scalars(select(AppSetting))
    stored: dict[str, Any] = {row.key: json.loads(row.value) for row in rows}
    return InstallSettings(**{k: v for k, v in stored.items() if k in InstallSettings.model_fields})


async def save(db: AsyncSession, settings: InstallSettings) -> None:
    for key, value in settings.model_dump().items():
        await db.merge(AppSetting(key=key, value=json.dumps(value)))
    await db.flush()
