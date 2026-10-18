"""HP Color LaserJet Pro (M283fdw and similar) through its Embedded Web Server.

The firmware rejects PKCS#12 files that contain intermediate certificates, so this
Plugin receives a bundle with only the leaf and key. Flow (reverse-engineered):
  1. GET  /Security/Certificates          session cookie + CSRF token
  2. POST /Security/Certificates/Import   multipart: the .pfx, its passphrase, the token
  3. wait for the EWS daemon to cycle, then verify the served fingerprint

Credentials: password (the EWS admin password); username defaults to `admin`.
Options (for firmware that names things differently):
  csrf_field       default `CSRFToken`
  file_field       default `certificate`
  password_field   default `password`
  cycle_wait       seconds to wait before verifying (default 15)
  verify_timeout   seconds to keep verifying after that (default 60)
"""

from __future__ import annotations

import asyncio
import re

import httpx

from certfabric.plugins.base import (
    BaseDevicePlugin,
    PluginError,
    PluginValidationResult,
    describe,
    device_tls_context,
)

TIMEOUT_SECONDS = 30
CERTIFICATES_PAGE = "/Security/Certificates"
IMPORT_PATH = "/Security/Certificates/Import"


class HpProEwsPlugin(BaseDevicePlugin):
    plugin_id = "hp_pro_ews"
    plugin_name = "HP LaserJet Pro (EWS)"
    target_category = "printer"
    supported_models = ["HP Color LaserJet Pro M283fdw", "HP Color LaserJet Pro MFP M28x series"]
    pfx_include_chain = False

    def _client(self) -> httpx.AsyncClient:
        creds = self.credentials
        auth = (creds.username or "admin", creds.password) if creds.password else None
        # The printer's current certificate is the one being replaced, so it cannot be trusted.
        return httpx.AsyncClient(
            base_url=f"https://{self.host}:{self.port}",
            auth=auth,
            verify=device_tls_context(),
            timeout=TIMEOUT_SECONDS,
        )

    def _csrf_token(self, html: str) -> str:
        field = re.escape(self.options.get("csrf_field", "CSRFToken"))
        for pattern in (
            rf'name="{field}"[^>]*value="([^"]+)"',
            rf'value="([^"]+)"[^>]*name="{field}"',
        ):
            if match := re.search(pattern, html):
                return match.group(1)
        raise PluginError("No CSRF token found on the certificates page; is this an HP Pro EWS?")

    async def _open_session(self, client: httpx.AsyncClient) -> str:
        response = await client.get(CERTIFICATES_PAGE)
        if response.status_code == 401:
            raise PluginError("The printer rejected the admin password")
        if response.status_code >= 400:
            raise PluginError(f"Certificates page returned {response.status_code}")
        return self._csrf_token(response.text)

    async def test_connection(self) -> PluginValidationResult:
        try:
            async with self._client() as client:
                await self._open_session(client)
        except PluginError as exc:
            return PluginValidationResult(success=False, message=str(exc))
        except httpx.HTTPError as exc:
            return PluginValidationResult(success=False, message=f"Printer unreachable: {describe(exc)}")
        return PluginValidationResult(success=True, message="Signed in to the printer's certificate page")

    async def deploy_certificate(
        self, cert_pem: str, privkey_pem: str, fullchain_pem: str, pfx_bundle: bytes, pfx_password: str | None
    ) -> bool:
        if not pfx_password:
            raise PluginError("The printer needs a PKCS#12 passphrase")
        try:
            async with self._client() as client:
                token = await self._open_session(client)
                self.log("Uploading the PKCS#12 bundle (leaf and key only) to the printer")
                response = await client.post(
                    IMPORT_PATH,
                    data={
                        self.options.get("password_field", "password"): pfx_password,
                        self.options.get("csrf_field", "CSRFToken"): token,
                    },
                    files={
                        self.options.get("file_field", "certificate"): (
                            "certfabric.pfx",
                            pfx_bundle,
                            "application/x-pkcs12",
                        )
                    },
                )
        except httpx.HTTPError as exc:
            raise PluginError(f"Printer unreachable: {describe(exc)}") from None
        if response.status_code == 401:
            raise PluginError("The printer rejected the admin password")
        if response.status_code >= 400:
            raise PluginError(f"The printer refused the certificate ({response.status_code})")
        self.log("Upload accepted; waiting for the web server to restart")
        return True

    async def post_deployment_verify(self, expected_fingerprint: str) -> bool:
        await asyncio.sleep(float(self.options.get("cycle_wait", 15)))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + float(self.options.get("verify_timeout", 60))
        while True:
            if await self.served_fingerprint() == expected_fingerprint:
                return True
            if loop.time() >= deadline:
                return False
            await asyncio.sleep(min(3.0, max(0.1, deadline - loop.time())))
