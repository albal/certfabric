"""Certificates: request issuance and read what is stored. Private keys are never returned."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certfabric import app_settings, certificates
from certfabric.acme import KeyType, validate_domain
from certfabric.api.deps import get_db
from certfabric.models import Certificate, DnsProvider

router = APIRouter(prefix="/api/certificates", tags=["certificates"])


class CertificateRequest(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=100, examples=[["*.lan.example.com"]])
    dns_provider_id: str
    key_type: KeyType = "RSA2048"

    @field_validator("domains")
    @classmethod
    def _domains(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(validate_domain(d) for d in value))


class JobStarted(BaseModel):
    job_id: str


class CertificateOut(BaseModel):
    id: str
    domain_primary: str
    sans: list[str]
    dns_provider_id: str
    key_type: str
    serial_number: str
    fingerprint_sha256: str
    issued_at: datetime
    expires_at: datetime
    status: str
    superseded_by: str | None
    has_private_key: bool
    renewal_attempted_at: datetime | None
    renewal_error: str | None


def _out(cert: Certificate, now: datetime, threshold_days: int) -> CertificateOut:
    return CertificateOut(
        id=cert.id,
        domain_primary=cert.domain_primary,
        sans=cert.san_list,
        dns_provider_id=cert.dns_provider_id,
        key_type=cert.key_type,
        serial_number=cert.serial_number,
        fingerprint_sha256=cert.fingerprint_sha256,
        issued_at=cert.issued_at,
        expires_at=cert.expires_at,
        status=certificates.derived_status(cert, now, threshold_days),
        superseded_by=cert.superseded_by,
        has_private_key=cert.privkey_pem_encrypted is not None,
        renewal_attempted_at=cert.renewal_attempted_at,
        renewal_error=cert.renewal_error,
    )


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def request_certificate(
    body: CertificateRequest, request: Request, db: AsyncSession = Depends(get_db)
) -> JobStarted:
    if await db.get(DnsProvider, body.dns_provider_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unknown DNS Provider")
    state = request.app.state

    async def run(job):  # type: ignore[no-untyped-def]
        return await certificates.issue(
            state, job, domains=body.domains, dns_provider_id=body.dns_provider_id, key_type=body.key_type
        )

    return JobStarted(job_id=state.jobs.start("issuance", run).id)


@router.get("")
async def list_certificates(request: Request, db: AsyncSession = Depends(get_db)) -> list[CertificateOut]:
    threshold = (await app_settings.load(db)).renewal_threshold_days
    now = request.app.state.clock.now()
    rows = await db.scalars(select(Certificate).order_by(Certificate.issued_at))
    return [_out(c, now, threshold) for c in rows]


@router.get("/{certificate_id}")
async def get_certificate(
    certificate_id: str, request: Request, db: AsyncSession = Depends(get_db)
) -> CertificateOut:
    cert = await db.get(Certificate, certificate_id)
    if cert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Certificate not found")
    threshold = (await app_settings.load(db)).renewal_threshold_days
    return _out(cert, request.app.state.clock.now(), threshold)
