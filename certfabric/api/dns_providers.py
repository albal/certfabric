"""DNS Providers: credentials CertFabric hands to `acme.sh` for DNS-01 challenges."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from certfabric.api.deps import get_db
from certfabric.models import DnsProvider
from certfabric.secrets_display import mask_all
from certfabric.vault import Vault

router = APIRouter(prefix="/api/dns-providers", tags=["dns-providers"])

DNS_TYPE_PATTERN = r"^dns_[a-z0-9_]+$"
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Credentials become environment variables for acme.sh; these would change how it runs.
_FORBIDDEN_ENV = re.compile(r"^(PATH|HOME|SHELL|IFS|ENV|BASH_ENV|LD_.*|DYLD_.*|PYTHON.*)$")


def _check_credentials(value: dict[str, str] | None) -> dict[str, str] | None:
    if value is None:
        return None
    if not value:
        raise ValueError("At least one credential is required")
    for key in value:
        if not _ENV_NAME.match(key) or _FORBIDDEN_ENV.match(key):
            raise ValueError(f"{key!r} is not an allowed credential name")
    return value


class DnsProviderCreate(BaseModel):
    name: str = Field(min_length=1)
    acme_dns_type: str = Field(pattern=DNS_TYPE_PATTERN, examples=["dns_cf"])
    credentials: dict[str, str]

    _validate = field_validator("credentials")(_check_credentials)


class DnsProviderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1)
    acme_dns_type: str | None = Field(default=None, pattern=DNS_TYPE_PATTERN)
    credentials: dict[str, str] | None = None

    _validate = field_validator("credentials")(_check_credentials)


class DnsProviderOut(BaseModel):
    id: str
    name: str
    acme_dns_type: str
    credentials: dict[str, str] = Field(description="Masked; secrets are never returned in full")
    created_at: datetime


def _out(provider: DnsProvider, vault: Vault) -> DnsProviderOut:
    return DnsProviderOut(
        id=provider.id,
        name=provider.name,
        acme_dns_type=provider.acme_dns_type,
        credentials=mask_all(vault.decrypt_json(provider.encrypted_credentials)),
        created_at=provider.created_at,
    )


async def _get(db: AsyncSession, provider_id: str) -> DnsProvider:
    provider = await db.get(DnsProvider, provider_id)
    if provider is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "DNS Provider not found")
    return provider


@router.get("")
async def list_providers(request: Request, db: AsyncSession = Depends(get_db)) -> list[DnsProviderOut]:
    providers = await db.scalars(select(DnsProvider).order_by(DnsProvider.created_at))
    return [_out(p, request.app.state.vault) for p in providers]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_provider(
    body: DnsProviderCreate, request: Request, db: AsyncSession = Depends(get_db)
) -> DnsProviderOut:
    vault: Vault = request.app.state.vault
    provider = DnsProvider(
        id=uuid.uuid4().hex,
        name=body.name,
        acme_dns_type=body.acme_dns_type,
        encrypted_credentials=vault.encrypt_json(body.credentials),
        created_at=request.app.state.clock.now(),
    )
    db.add(provider)
    await db.flush()
    return _out(provider, vault)


@router.get("/{provider_id}")
async def get_provider(provider_id: str, request: Request, db: AsyncSession = Depends(get_db)) -> DnsProviderOut:
    return _out(await _get(db, provider_id), request.app.state.vault)


@router.patch("/{provider_id}")
async def update_provider(
    provider_id: str, body: DnsProviderUpdate, request: Request, db: AsyncSession = Depends(get_db)
) -> DnsProviderOut:
    vault: Vault = request.app.state.vault
    provider = await _get(db, provider_id)
    if body.name is not None:
        provider.name = body.name
    if body.acme_dns_type is not None:
        provider.acme_dns_type = body.acme_dns_type
    if body.credentials is not None:
        provider.encrypted_credentials = vault.encrypt_json(body.credentials)
    await db.flush()
    return _out(provider, vault)


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(provider_id: str, db: AsyncSession = Depends(get_db)) -> None:
    await db.delete(await _get(db, provider_id))
    try:
        await db.flush()
    except IntegrityError:
        # Certificates reference DNS Providers with ON DELETE RESTRICT.
        raise HTTPException(
            status.HTTP_409_CONFLICT, "DNS Provider is used by a Certificate and cannot be removed"
        ) from None
