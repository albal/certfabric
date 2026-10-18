"""The Probe: a non-invasive TLS handshake that reads a Device's Presented Certificate.

It never authenticates, never sends application data, and accepts any certificate:
it observes what is served, it does not trust it. Legacy protocol versions and ciphers
are allowed because the devices CertFabric manages are often old.
"""

from __future__ import annotations

import asyncio
import ssl
import warnings
from dataclasses import dataclass

from certfabric.x509util import CertInfo, info_from_der

PROBE_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class ProbeResult:
    presented: CertInfo | None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.presented is not None


def _context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = ssl.TLSVersion.TLSv1
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass  # The local OpenSSL refuses legacy settings; probe with its defaults.
    return context


async def probe(host: str, port: int, sni: str | None = None, timeout: float = PROBE_TIMEOUT_SECONDS) -> ProbeResult:
    try:
        async with asyncio.timeout(timeout):
            _reader, writer = await asyncio.open_connection(
                host, port, ssl=_context(), server_hostname=sni or host
            )
            try:
                der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ssl.SSLError, ConnectionError):
                    pass
    except TimeoutError:
        return ProbeResult(None, f"Timed out after {timeout:g}s")
    except (OSError, ssl.SSLError) as exc:
        return ProbeResult(None, f"{type(exc).__name__}: {exc}")
    if not der:
        return ProbeResult(None, "Device presented no certificate")
    try:
        return ProbeResult(info_from_der(der))
    except ValueError as exc:
        return ProbeResult(None, f"Presented certificate could not be parsed: {exc}")
