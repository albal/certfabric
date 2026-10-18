"""Certificates for fake Devices: factory self-signed ones, and CertFabric-issued ones read from the DB."""

from __future__ import annotations

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def self_signed(common_name: str, now: datetime, days: int = 3650) -> tuple[str, str]:
    """A factory-style self-signed certificate and key, as PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem


def fingerprint(cert_pem: str) -> str:
    return x509.load_pem_x509_certificate(cert_pem.encode()).fingerprint(hashes.SHA256()).hex()
