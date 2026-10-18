"""Reading certificates and building PKCS#12 bundles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class CertInfo:
    common_name: str | None
    sans: list[str]
    issuer: str
    serial_number: str
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime


def _info(cert: x509.Certificate) -> CertInfo:
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(n) for n in sans.get_values_for_type(x509.DNSName)]
        names += [str(ip) for ip in sans.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return CertInfo(
        common_name=str(cns[0].value) if cns else None,
        sans=names,
        issuer=cert.issuer.rfc4514_string(),
        serial_number=format(cert.serial_number, "x"),
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
    )


def info_from_pem(pem: str) -> CertInfo:
    return _info(x509.load_pem_x509_certificate(pem.encode()))


def info_from_der(der: bytes) -> CertInfo:
    return _info(x509.load_der_x509_certificate(der))


def split_pem_chain(fullchain_pem: str) -> list[str]:
    marker = "-----END CERTIFICATE-----"
    return [part.strip() + "\n" + marker + "\n" for part in fullchain_pem.split(marker) if part.strip()]


def check_key_matches(cert_pem: str, key_pem: str) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    public = serialization.PublicFormat.SubjectPublicKeyInfo
    encoding = serialization.Encoding.DER
    return cert.public_key().public_bytes(encoding, public) == key.public_key().public_bytes(encoding, public)


def build_pkcs12(
    cert_pem: str, key_pem: str, passphrase: str, chain_pems: list[str] | None = None
) -> bytes:
    """A PKCS#12 bundle of the leaf and key, plus `chain_pems` when the target accepts a chain."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    cas = [x509.load_pem_x509_certificate(p.encode()) for p in chain_pems or []]
    return pkcs12.serialize_key_and_certificates(
        name=None,
        key=key,  # type: ignore[arg-type]
        cert=cert,
        cas=cas or None,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
    )
