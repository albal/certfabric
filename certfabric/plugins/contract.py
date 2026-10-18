"""Reusable contract tests every Plugin must pass (Seam 2).

Subclass `PluginContract` in your Plugin's test module and provide these fixtures:

  make_plugin(credentials, log)  -> a Plugin instance pointed at a simulated device
  good_credentials               -> DeviceCredentials the simulator accepts
  bad_credentials                -> DeviceCredentials the simulator rejects
  served_fingerprint()           -> async callable: SHA-256 the simulator serves now

The suite needs pytest and pytest-asyncio. Example:

    class TestMyPlugin(PluginContract):
        @pytest.fixture
        def make_plugin(self, simulator): ...
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certfabric.plugins.base import TARGET_CATEGORIES, BaseDevicePlugin, PluginError
from certfabric.x509util import build_pkcs12


@dataclass(frozen=True)
class CertificateMaterial:
    cert_pem: str
    key_pem: str
    fullchain_pem: str
    fingerprint_sha256: str

    def pkcs12(self, passphrase: str) -> bytes:
        return build_pkcs12(self.cert_pem, self.key_pem, passphrase)


def make_certificate(common_name: str = "device.test") -> CertificateMaterial:
    """A CA-signed RSA 2048 leaf like the ones CertFabric issues."""
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Contract Test CA")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )  # fmt: skip
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )  # fmt: skip
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()  # noqa: E731
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return CertificateMaterial(pem(leaf), key_pem, pem(leaf) + pem(ca), leaf.fingerprint(hashes.SHA256()).hex())


PASSPHRASE = "contract-test-passphrase"


class PluginContract:
    @pytest.fixture
    def certificate(self) -> CertificateMaterial:
        return make_certificate()

    @pytest.fixture
    def log_lines(self) -> list[str]:
        return []

    async def _deploy(self, plugin: BaseDevicePlugin, cert: CertificateMaterial) -> bool:
        passphrase = PASSPHRASE[: plugin.pfx_passphrase_max_length]
        return await plugin.deploy_certificate(
            cert.cert_pem, cert.key_pem, cert.fullchain_pem, cert.pkcs12(passphrase), passphrase
        )

    def test_metadata(self, make_plugin, good_credentials, log_lines):
        plugin = make_plugin(good_credentials, log_lines.append)
        assert re.fullmatch(r"[a-z0-9_]+", plugin.plugin_id)
        assert plugin.plugin_name
        assert plugin.target_category in TARGET_CATEGORIES
        assert isinstance(plugin.supported_models, list) and plugin.supported_models

    @pytest.mark.asyncio
    async def test_connection_succeeds_with_good_credentials(self, make_plugin, good_credentials, log_lines):
        result = await make_plugin(good_credentials, log_lines.append).test_connection()
        assert result.success, result.message

    @pytest.mark.asyncio
    async def test_connection_reports_bad_credentials_without_raising(self, make_plugin, bad_credentials, log_lines):
        result = await make_plugin(bad_credentials, log_lines.append).test_connection()
        assert not result.success
        assert result.message

    @pytest.mark.asyncio
    async def test_deploy_makes_the_device_serve_the_certificate(
        self, make_plugin, good_credentials, certificate, served_fingerprint, log_lines
    ):
        plugin = make_plugin(good_credentials, log_lines.append)
        assert await self._deploy(plugin, certificate) is True
        assert await plugin.post_deployment_verify(certificate.fingerprint_sha256) is True
        assert await served_fingerprint() == certificate.fingerprint_sha256

    @pytest.mark.asyncio
    async def test_verify_rejects_a_different_fingerprint(self, make_plugin, good_credentials, certificate, log_lines):
        plugin = make_plugin(good_credentials, log_lines.append)
        await self._deploy(plugin, certificate)
        assert await plugin.post_deployment_verify("0" * 64) is False

    @pytest.mark.asyncio
    async def test_deploy_with_bad_credentials_fails_cleanly(
        self, make_plugin, bad_credentials, certificate, served_fingerprint, log_lines
    ):
        plugin = make_plugin(bad_credentials, log_lines.append)
        try:
            assert await self._deploy(plugin, certificate) is False
        except PluginError:
            pass
        assert await served_fingerprint() != certificate.fingerprint_sha256

    @pytest.mark.asyncio
    async def test_never_logs_secrets(self, make_plugin, good_credentials, certificate, log_lines):
        plugin = make_plugin(good_credentials, log_lines.append)
        await plugin.test_connection()
        await self._deploy(plugin, certificate)
        output = "\n".join(log_lines)
        passphrase = PASSPHRASE[: plugin.pfx_passphrase_max_length]
        for secret in [*good_credentials.secrets(), passphrase, certificate.key_pem.splitlines()[1]]:
            assert secret not in output
