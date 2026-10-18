"""Devices: what CertFabric probes and deploys to."""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certfabric import devices
from certfabric.api.deps import get_db
from certfabric.models import Device
from certfabric.probe import probe
from certfabric.secrets_display import mask
from certfabric.vault import Vault

router = APIRouter(prefix="/api/devices", tags=["devices"])

_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_PLUGIN_ID = r"^[a-z0-9_]+$"


def _check_host(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().rstrip(".").lower()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not _HOSTNAME.match(value):
        raise ValueError(f"{value!r} is not a valid hostname or IP address")
    return value


def _check_sni(value: str | None) -> str | None:
    value = _check_host(value)
    if value is not None and _is_ip(value):
        raise ValueError("sni must be a hostname, not an IP address")
    return value


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class DeviceCredentials(BaseModel):
    username: str | None = None
    password: str | None = None
    api_token: str | None = None
    pfx_passphrase: str | None = Field(default=None, description="Only for devices that need a fixed PKCS#12 passphrase")
    extra: dict[str, str] = Field(default_factory=dict, description="Additional secrets a Plugin needs")


class DeviceCredentialsOut(BaseModel):
    username: str | None
    password: str | None
    api_token: str | None
    pfx_passphrase: str | None
    extra: dict[str, str]


class DeviceCreate(BaseModel):
    name: str = Field(min_length=1)
    hostname: str
    port: int = Field(default=443, ge=1, le=65535)
    sni: str | None = Field(default=None, description="Name to send in the TLS handshake and match the Certificate against")
    plugin_id: str = Field(pattern=_PLUGIN_ID)
    plugin_options: dict[str, Any] = Field(default_factory=dict, description="Non-secret Plugin settings")
    credentials: DeviceCredentials = Field(default_factory=DeviceCredentials)
    polling_interval_minutes: int = Field(default=360, ge=5, le=7 * 24 * 60)

    _host = field_validator("hostname")(_check_host)
    _sni = field_validator("sni")(_check_sni)


class DeviceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1)
    hostname: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    sni: str | None = None
    plugin_id: str | None = Field(default=None, pattern=_PLUGIN_ID)
    plugin_options: dict[str, Any] | None = None
    credentials: DeviceCredentials | None = None
    polling_interval_minutes: int | None = Field(default=None, ge=5, le=7 * 24 * 60)

    _host = field_validator("hostname")(_check_host)
    _sni = field_validator("sni")(_check_sni)


class PresentedCertificate(BaseModel):
    common_name: str | None
    sans: list[str]
    issuer: str | None
    serial_number: str | None
    fingerprint_sha256: str
    expires_at: datetime | None


class DeviceOut(BaseModel):
    id: str
    name: str
    hostname: str
    port: int
    sni: str | None
    plugin_id: str
    plugin_options: dict[str, Any]
    credentials: DeviceCredentialsOut
    polling_interval_minutes: int
    assigned_certificate_id: str | None
    state: str = Field(description="MONITOR_ONLY when no Certificate is assigned, otherwise the classification")
    presented_certificate: PresentedCertificate | None
    consecutive_probe_failures: int
    last_probe_error: str | None
    last_scanned_at: datetime | None
    created_at: datetime


class ConnectionTestResult(BaseModel):
    success: bool
    message: str
    presented_certificate: PresentedCertificate | None = None


def _credentials(device: Device, vault: Vault) -> DeviceCredentials:
    if not device.encrypted_credentials:
        return DeviceCredentials()
    return DeviceCredentials(**vault.decrypt_json(device.encrypted_credentials))


def _masked(creds: DeviceCredentials) -> DeviceCredentialsOut:
    secret = lambda v: mask(v) if v else None  # noqa: E731
    return DeviceCredentialsOut(
        username=creds.username,
        password=secret(creds.password),
        api_token=secret(creds.api_token),
        pfx_passphrase=secret(creds.pfx_passphrase),
        extra={k: mask(v) for k, v in creds.extra.items()},
    )


def device_out(device: Device, vault: Vault) -> DeviceOut:
    presented = None
    if device.presented_fingerprint:
        presented = PresentedCertificate(
            common_name=device.presented_common_name,
            sans=device.presented_sans or [],
            issuer=device.presented_issuer,
            serial_number=device.presented_serial,
            fingerprint_sha256=device.presented_fingerprint,
            expires_at=device.presented_expires_at,
        )
    return DeviceOut(
        id=device.id,
        name=device.name,
        hostname=device.hostname,
        port=device.port,
        sni=device.sni,
        plugin_id=device.plugin_id,
        plugin_options=device.plugin_options,
        credentials=_masked(_credentials(device, vault)),
        polling_interval_minutes=device.polling_interval_minutes,
        assigned_certificate_id=device.assigned_cert_id,
        state="MONITOR_ONLY" if device.assigned_cert_id is None else device.drift_status,
        presented_certificate=presented,
        consecutive_probe_failures=device.consecutive_probe_failures,
        last_probe_error=device.last_probe_error,
        last_scanned_at=device.last_scanned_at,
        created_at=device.created_at,
    )


async def get_device_or_404(db: AsyncSession, device_id: str) -> Device:
    device = await db.get(Device, device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    return device


@router.get("")
async def list_devices(request: Request, db: AsyncSession = Depends(get_db)) -> list[DeviceOut]:
    rows = await db.scalars(select(Device).order_by(Device.name))
    return [device_out(d, request.app.state.vault) for d in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_device(body: DeviceCreate, request: Request, db: AsyncSession = Depends(get_db)) -> DeviceOut:
    vault: Vault = request.app.state.vault
    device = Device(
        id=uuid.uuid4().hex,
        name=body.name,
        hostname=body.hostname,
        port=body.port,
        sni=body.sni,
        plugin_id=body.plugin_id,
        plugin_options=body.plugin_options,
        encrypted_credentials=vault.encrypt_json(body.credentials.model_dump()),
        polling_interval_minutes=body.polling_interval_minutes,
        drift_status="UNKNOWN",
        consecutive_probe_failures=0,
        consecutive_deploy_failures=0,
        created_at=request.app.state.clock.now(),
    )
    db.add(device)
    await db.flush()
    return device_out(device, vault)


@router.post("/test-connection")
async def test_connection(body: DeviceCreate) -> ConnectionTestResult:
    """Check a Device's details before saving them."""
    result = await probe(body.hostname, body.port, body.sni)
    if result.presented is None:
        return ConnectionTestResult(success=False, message=f"TLS connection failed: {result.error}")
    p = result.presented
    return ConnectionTestResult(
        success=True,
        message="TLS connection succeeded",
        presented_certificate=PresentedCertificate(
            common_name=p.common_name,
            sans=p.sans,
            issuer=p.issuer,
            serial_number=p.serial_number,
            fingerprint_sha256=p.fingerprint_sha256,
            expires_at=p.not_after,
        ),
    )


@router.get("/{device_id}")
async def get_device(device_id: str, request: Request, db: AsyncSession = Depends(get_db)) -> DeviceOut:
    return device_out(await get_device_or_404(db, device_id), request.app.state.vault)


@router.patch("/{device_id}")
async def update_device(
    device_id: str, body: DeviceUpdate, request: Request, db: AsyncSession = Depends(get_db)
) -> DeviceOut:
    vault: Vault = request.app.state.vault
    device = await get_device_or_404(db, device_id)
    changes = body.model_dump(exclude_unset=True, exclude={"credentials"})
    for field, value in changes.items():
        if value is None and field != "sni":
            continue
        setattr(device, field, value)
    if body.credentials is not None:
        device.encrypted_credentials = vault.encrypt_json(body.credentials.model_dump())
    await db.flush()
    return device_out(device, vault)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(device_id: str, db: AsyncSession = Depends(get_db)) -> None:
    await db.delete(await get_device_or_404(db, device_id))


@router.post("/{device_id}/probe")
async def probe_now(device_id: str, request: Request) -> DeviceOut:
    """Probe the Device immediately instead of waiting for its interval."""
    state = request.app.state
    async with state.db.session() as db:
        await get_device_or_404(db, device_id)
    await devices.probe_device(state, device_id)
    async with state.db.session() as db:
        return device_out(await get_device_or_404(db, device_id), state.vault)
