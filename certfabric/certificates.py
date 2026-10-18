"""Issuing Certificates through AcmeRunner and storing what comes back."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from starlette.datastructures import State

from certfabric import app_settings
from certfabric.acme import AcmeError, KeyType
from certfabric.jobs import Job, JobFailed
from certfabric.models import Certificate, DnsProvider
from certfabric.x509util import check_key_matches, info_from_pem


def covers(sans: list[str], name: str) -> bool:
    """Whether a Certificate with these SANs is valid for `name` (a wildcard covers one label)."""
    name = name.lower().rstrip(".")
    for san in (s.lower() for s in sans):
        if san == name:
            return True
        if san.startswith("*.") and "." in name and name.split(".", 1)[1] == san[2:]:
            return True
    return False


def derived_status(cert: Certificate, now: datetime, threshold_days: int) -> str:
    if cert.status != "VALID":
        return cert.status
    if cert.expires_at <= now:
        return "EXPIRED"
    if cert.expires_at - now <= timedelta(days=threshold_days):
        return "EXPIRING"
    return "VALID"


async def issue(
    state: State, job: Job, *, domains: list[str], dns_provider_id: str, key_type: KeyType
) -> dict[str, Any]:
    """Job body: run acme.sh, then store the Certificate. Nothing is stored if any step fails."""
    async with state.db.session() as db:
        provider = await db.get(DnsProvider, dns_provider_id)
        if provider is None:
            raise JobFailed("DNS Provider no longer exists")
        credentials: dict[str, str] = state.vault.decrypt_json(provider.encrypted_credentials)
        install = await app_settings.load(db)
    job.redactor.add(credentials.values())
    server = install.acme_server()
    job.write(f"Requesting a {key_type} certificate for {', '.join(domains)} from {server}")

    try:
        files = await state.acme.issue(
            domains=domains,
            dns_type=provider.acme_dns_type,
            credentials=credentials,
            key_type=key_type,
            server=server,
            on_output=job.write,
        )
    except AcmeError as exc:
        raise JobFailed(str(exc)) from None
    if not check_key_matches(files.cert_pem, files.key_pem):
        raise JobFailed("acme.sh returned a private key that does not match the certificate")

    info = info_from_pem(files.cert_pem)
    certificate = Certificate(
        id=uuid.uuid4().hex,
        domain_primary=domains[0],
        san_list=info.sans or domains,
        dns_provider_id=dns_provider_id,
        key_type=key_type,
        cert_pem=files.cert_pem,
        fullchain_pem=files.fullchain_pem,
        privkey_pem_encrypted=state.vault.encrypt(files.key_pem),
        serial_number=info.serial_number,
        fingerprint_sha256=info.fingerprint_sha256,
        issued_at=info.not_before,
        expires_at=info.not_after,
        status="VALID",
    )
    async with state.db.session() as db, db.begin():
        db.add(certificate)
    job.write(f"Stored Certificate {certificate.id}, expires {info.not_after:%Y-%m-%d}")
    return {"certificate_id": certificate.id}
