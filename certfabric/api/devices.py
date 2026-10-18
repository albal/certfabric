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
from certfabric.certificates import covers
from certfabric.deployments import DeploymentInProgress, DeploymentRefused, reset_failures
from certfabric.models import Certificate, DeploymentLog, Device
from certfabric.plugins.base import DeviceCredentials
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
    certificate_id: str | None = Field(default=None, description="Assign a Certificate; omit for Monitor-only")

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
    state: str = Field(description="UNREACHABLE, MONITOR_ONLY when no Certificate is assigned, otherwise the classification")
    presented_certificate: PresentedCertificate | None
    consecutive_probe_failures: int
    consecutive_deploy_failures: int
    next_retry_at: datetime | None
    last_probe_error: str | None
    last_scanned_at: datetime | None
    created_at: datetime


class ConnectionTestResult(BaseModel):
    success: bool
    message: str
    presented_certificate: PresentedCertificate | None = None


class Assignment(BaseModel):
    certificate_id: str | None


class JobStarted(BaseModel):
    job_id: str


class DeploymentOut(BaseModel):
    id: str
    certificate_id: str
    trigger_source: str
    success: bool
    execution_time_ms: int
    log_output: str | None
    timestamp: datetime


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


def _state(device: Device) -> str:
    if device.drift_status == "UNREACHABLE":
        return "UNREACHABLE"  # Worth showing even for a Monitor-only Device.
    return "MONITOR_ONLY" if device.assigned_cert_id is None else device.drift_status


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
        state=_state(device),
        presented_certificate=presented,
        consecutive_probe_failures=device.consecutive_probe_failures,
        consecutive_deploy_failures=device.consecutive_deploy_failures,
        next_retry_at=device.next_retry_at,
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


def _require_plugin(request: Request, plugin_id: str) -> None:
    if request.app.state.plugins.get(plugin_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Plugin {plugin_id!r} is not installed")


async def _check_assignment(db: AsyncSession, device: Device, certificate_id: str | None) -> None:
    """A Certificate can only be assigned to a Device whose name its SANs cover."""
    if certificate_id is None:
        return
    cert = await db.get(Certificate, certificate_id)
    if cert is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unknown Certificate")
    if cert.status in ("SUPERSEDED", "REVOKED"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Certificate is {cert.status.lower()}")
    name = device.sni or device.hostname
    if _is_ip(name):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Device is addressed by IP: set its sni to the hostname the Certificate should cover",
        )
    if not covers(cert.san_list, name):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Certificate ({', '.join(cert.san_list)}) does not cover {name}",
        )


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_device(body: DeviceCreate, request: Request, db: AsyncSession = Depends(get_db)) -> DeviceOut:
    vault: Vault = request.app.state.vault
    _require_plugin(request, body.plugin_id)
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
    await _check_assignment(db, device, body.certificate_id)
    device.assigned_cert_id = body.certificate_id
    db.add(device)
    await db.flush()
    return device_out(device, vault)


async def _test(request: Request, device: DeviceCreate | Device, credentials: DeviceCredentials) -> ConnectionTestResult:
    """TLS reachability, then the Plugin's own check of credentials and compatibility."""
    result = await probe(device.hostname, device.port, device.sni)
    if result.presented is None:
        return ConnectionTestResult(success=False, message=f"TLS connection failed: {result.error}")
    plugin_cls = request.app.state.plugins.get(device.plugin_id)
    if plugin_cls is None:
        return ConnectionTestResult(success=False, message=f"Plugin {device.plugin_id!r} is not installed")
    plugin = plugin_cls(device.hostname, device.port, credentials, options=device.plugin_options, sni=device.sni)
    try:
        check = await plugin.test_connection()
    except Exception as exc:  # A Plugin bug must not break the API.
        check_success, check_message = False, f"Plugin error: {type(exc).__name__}: {exc}"
    else:
        check_success, check_message = check.success, check.message
    p = result.presented
    return ConnectionTestResult(
        success=check_success,
        message=check_message,
        presented_certificate=PresentedCertificate(
            common_name=p.common_name,
            sans=p.sans,
            issuer=p.issuer,
            serial_number=p.serial_number,
            fingerprint_sha256=p.fingerprint_sha256,
            expires_at=p.not_after,
        ),
    )


@router.post("/test-connection")
async def test_connection(body: DeviceCreate, request: Request) -> ConnectionTestResult:
    """Check a Device's details before saving them."""
    return await _test(request, body, body.credentials)


@router.get("/{device_id}")
async def get_device(device_id: str, request: Request, db: AsyncSession = Depends(get_db)) -> DeviceOut:
    return device_out(await get_device_or_404(db, device_id), request.app.state.vault)


@router.patch("/{device_id}")
async def update_device(
    device_id: str, body: DeviceUpdate, request: Request, db: AsyncSession = Depends(get_db)
) -> DeviceOut:
    vault: Vault = request.app.state.vault
    device = await get_device_or_404(db, device_id)
    if body.plugin_id is not None:
        _require_plugin(request, body.plugin_id)
    changes = body.model_dump(exclude_unset=True, exclude={"credentials"})
    for field, value in changes.items():
        if value is None and field != "sni":
            continue
        setattr(device, field, value)
    if body.credentials is not None:
        device.encrypted_credentials = vault.encrypt_json(body.credentials.model_dump())
        reset_failures(device)  # New credentials are worth trying again.
    if {"hostname", "sni"} & changes.keys():
        await _check_assignment(db, device, device.assigned_cert_id)
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


@router.post("/{device_id}/test-connection")
async def test_saved_connection(device_id: str, request: Request, db: AsyncSession = Depends(get_db)) -> ConnectionTestResult:
    device = await get_device_or_404(db, device_id)
    return await _test(request, device, _credentials(device, request.app.state.vault))


@router.put("/{device_id}/certificate")
async def assign_certificate(
    device_id: str, body: Assignment, request: Request, db: AsyncSession = Depends(get_db)
) -> DeviceOut:
    """Assign a Certificate (or null for Monitor-only). The Device is deployed to separately."""
    device = await get_device_or_404(db, device_id)
    await _check_assignment(db, device, body.certificate_id)
    if device.assigned_cert_id != body.certificate_id:
        device.assigned_cert_id = body.certificate_id
        device.drift_status = "UNKNOWN"
    await db.flush()
    return device_out(device, request.app.state.vault)


@router.post("/{device_id}/deploy", status_code=status.HTTP_202_ACCEPTED)
async def redeploy_now(device_id: str, request: Request) -> JobStarted:
    """Redeploy Now: deploy the assigned Certificate immediately."""
    try:
        job = await request.app.state.deployer.start(device_id, "MANUAL")
    except DeploymentInProgress as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    except DeploymentRefused as exc:
        code = status.HTTP_404_NOT_FOUND if "not found" in str(exc) else status.HTTP_422_UNPROCESSABLE_CONTENT
        raise HTTPException(code, str(exc)) from None
    return JobStarted(job_id=job.id)


@router.get("/{device_id}/deployments")
async def deployment_history(device_id: str, db: AsyncSession = Depends(get_db)) -> list[DeploymentOut]:
    await get_device_or_404(db, device_id)
    rows = await db.scalars(
        select(DeploymentLog).where(DeploymentLog.device_id == device_id).order_by(DeploymentLog.timestamp.desc())
    )
    return [
        DeploymentOut(
            id=r.id,
            certificate_id=r.cert_id,
            trigger_source=r.trigger_source,
            success=r.success,
            execution_time_ms=r.execution_time_ms,
            log_output=r.log_output,
            timestamp=r.timestamp,
        )
        for r in rows
    ]
