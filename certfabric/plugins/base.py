"""The Plugin contract: every Device connector subclasses BaseDevicePlugin.

Trust boundary: a Plugin runs in-process and receives decrypted credentials and the
private key. Plugins are loaded only from directories on local disk; install only
Plugins you have read.
"""

from __future__ import annotations

import secrets
import string
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, ClassVar

from pydantic import BaseModel, Field, field_validator

# device_tls_context is re-exported for Plugins: pass it as httpx's `verify=` when talking to a Device.
from certfabric.probe import device_tls_context, probe  # noqa: F401

TARGET_CATEGORIES = ("printer", "bmc", "hypervisor", "network", "generic")


def trim_settings(values: dict[str, Any]) -> dict[str, Any]:
    """Keys and string values without surrounding whitespace, which pasted values often bring along."""
    return {key.strip(): value.strip() if isinstance(value, str) else value for key, value in values.items()}


class DeviceCredentials(BaseModel):
    username: str | None = None
    password: str | None = None
    api_token: str | None = None
    pfx_passphrase: str | None = Field(
        default=None, description="Only for devices that need a fixed PKCS#12 passphrase"
    )
    extra: dict[str, str] = Field(default_factory=dict, description="Additional secrets a Plugin needs")

    _trim_extra = field_validator("extra")(trim_settings)

    def secrets(self) -> list[str]:
        values = [self.password, self.api_token, self.pfx_passphrase, *self.extra.values()]
        return [v for v in values if v]


def generate_passphrase(max_length: int | None = None) -> str:
    """A fresh PKCS#12 passphrase: letters and digits only, since device forms can be fussy."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(min(24, max_length or 24)))


def describe(exc: BaseException) -> str:
    """An exception as a message for the admin, even when it has no text of its own."""
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


class PluginValidationResult(BaseModel):
    success: bool
    message: str
    details: dict[str, Any] | None = None


class PluginError(Exception):
    """Raised by a Plugin to fail an operation with a message meant for the admin."""


class BaseDevicePlugin(ABC):
    plugin_id: ClassVar[str]
    plugin_name: ClassVar[str]
    target_category: ClassVar[str]  # one of TARGET_CATEGORIES
    supported_models: ClassVar[list[str]]
    # Whether the PKCS#12 bundle handed to deploy_certificate includes the intermediate chain.
    pfx_include_chain: ClassVar[bool] = True
    # The longest PKCS#12 passphrase the device accepts, if it has a limit.
    pfx_passphrase_max_length: ClassVar[int | None] = None

    def __init__(
        self,
        host: str,
        port: int,
        credentials: DeviceCredentials,
        use_tls: bool = True,
        *,
        options: dict[str, Any] | None = None,
        sni: str | None = None,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.credentials = credentials
        self.use_tls = use_tls
        self.options = trim_settings(options or {})
        self.sni = sni
        self.log = log or (lambda _line: None)

    @abstractmethod
    async def test_connection(self) -> PluginValidationResult:
        """Validate IP reachability, authentication credentials, and hardware compatibility."""

    @abstractmethod
    async def deploy_certificate(
        self,
        cert_pem: str,
        privkey_pem: str,
        fullchain_pem: str,
        pfx_bundle: bytes,
        pfx_password: str | None,
    ) -> bool:
        """Execute device-specific push, upload, and service reload logic.

        Return False or raise PluginError on failure; anything written to `self.log` is
        redacted before it is stored or shown.
        """

    @abstractmethod
    async def post_deployment_verify(self, expected_fingerprint: str) -> bool:
        """Probe the device post-install to verify the new certificate is being actively served."""

    async def served_fingerprint(self) -> str | None:
        """Helper: the SHA-256 fingerprint the device is serving on its TLS port right now."""
        result = await probe(self.host, self.port, self.sni)
        if result.presented is None:
            self.log(f"Verification probe failed: {result.error}")
            return None
        return result.presented.fingerprint_sha256
