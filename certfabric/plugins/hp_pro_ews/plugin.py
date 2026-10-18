"""HP Color LaserJet Pro (M283fdw and similar) through its Embedded Web Server.

These printers run HP's EmWeb interface (`Server: Virata-EmWeb`). The Plugin walks the
same wizard as a browser, under Networking > Certificates:
  1. GET  /hp/device/set_config_networkCerts.html               the Certificates page
  2. POST /hp/device/set_config_networkCerts.html/config        "Configure" the printer certificate
  3. POST /hp/device/set_config_networkPrintCerts.html/config   "Import a Certificate and Private Key"
  4. GET  /hp/device/set_config_networkCertsImport.html         the upload form
  5. POST /hp/device/Certificate.pfx                            multipart: FileName (.pfx), Password, Finish
then waits for the web server to restart and verifies the served fingerprint.

The firmware takes a PKCS#12 bundle with only the leaf and key, and a passphrase of at
most 16 characters.

Credentials: password, if the printer has an admin password (sent with HTTP basic auth,
username `admin` unless one is set). Leave empty for a printer without one.
Options:
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
CERTIFICATES_PAGE = "/hp/device/set_config_networkCerts.html?tab=Networking&menu=NetCerts"
CONFIGURE = "/hp/device/set_config_networkCerts.html/config"
CHOOSE_ACTION = "/hp/device/set_config_networkPrintCerts.html/config"
IMPORT_PAGE = "/hp/device/set_config_networkCertsImport.html?tab=Networking&menu=NetCertImport"
CANCEL_IMPORT = "/hp/device/set_config_networkCertsImport.html/config"
UPLOAD = "/hp/device/Certificate.pfx"


class HpProEwsPlugin(BaseDevicePlugin):
    plugin_id = "hp_pro_ews"
    plugin_name = "HP LaserJet Pro (EWS)"
    target_category = "printer"
    supported_models = ["HP Color LaserJet Pro MFP M283fdw", "HP Color LaserJet Pro MFP M28x series"]
    pfx_include_chain = False
    pfx_passphrase_max_length = 16

    def _client(self) -> httpx.AsyncClient:
        creds = self.credentials
        auth = (creds.username or "admin", creds.password) if creds.password else None
        return httpx.AsyncClient(
            base_url=f"https://{self.host}:{self.port}",
            auth=auth,
            verify=device_tls_context(),
            timeout=TIMEOUT_SECONDS,
        )

    @staticmethod
    def _check(response: httpx.Response, step: str) -> None:
        if response.status_code == 401:
            raise PluginError("The printer rejected the admin password")
        # EmWeb answers each wizard step with 303 See Other to the next page.
        if response.status_code >= 400:
            raise PluginError(f"{step} returned {response.status_code}; is this an HP EmWeb printer?")

    async def _certificates_page(self, client: httpx.AsyncClient) -> str:
        response = await client.get(CERTIFICATES_PAGE)
        self._check(response, "The Certificates page")
        if 'name="ConfigurePrintCert"' not in response.text:
            raise PluginError("The Certificates page has no printer certificate settings; is this an HP EmWeb printer?")
        return response.text

    async def test_connection(self) -> PluginValidationResult:
        try:
            async with self._client() as client:
                page = await self._certificates_page(client)
        except PluginError as exc:
            return PluginValidationResult(success=False, message=str(exc))
        except httpx.HTTPError as exc:
            return PluginValidationResult(success=False, message=f"Printer unreachable: {describe(exc)}")
        title = re.search(r"<title>\s*(.*?)(?:&nbsp;|<)", page, re.S)
        model = title.group(1).strip() if title else "HP printer"
        return PluginValidationResult(success=True, message=f"Reached the certificate settings of {model}")

    async def deploy_certificate(
        self, cert_pem: str, privkey_pem: str, fullchain_pem: str, pfx_bundle: bytes, pfx_password: str | None
    ) -> bool:
        if not pfx_password:
            raise PluginError("The printer needs a PKCS#12 passphrase")
        try:
            async with self._client() as client:
                await self._certificates_page(client)
                self._check(await client.post(CONFIGURE, data={"ConfigurePrintCert": "Configure"}), "Configure")
                self._check(
                    await client.post(CHOOSE_ACTION, data={"ConfigOpt": "ImptCert", "Next": "Next"}),
                    "Choosing Import",
                )
                form = await client.get(IMPORT_PAGE)
                self._check(form, "The import page")
                if 'name="FileName"' not in form.text:
                    raise PluginError("The printer did not show its certificate import form")
                self.log("Uploading the PKCS#12 bundle (leaf and key only) to the printer")
                response = await client.post(
                    UPLOAD,
                    data={"Password": pfx_password, "Finish": "Finish"},
                    files={"FileName": ("certificate.pfx", pfx_bundle, "application/x-pkcs12")},
                )
                if response.status_code == 401:
                    raise PluginError("The printer rejected the admin password")
                if response.status_code >= 400:
                    # Leave the printer's wizard as we found it.
                    await client.post(CANCEL_IMPORT, data={"Cancel": "Cancel", "FinishText": "Finish"})
                    detail = re.sub(r"<[^>]+>|\s+", " ", response.text).strip()[:200]
                    raise PluginError(f"The printer refused the certificate ({response.status_code}) {detail}".strip())
        except httpx.HTTPError as exc:
            raise PluginError(f"Printer unreachable: {describe(exc)}") from None
        self.log(f"Upload accepted ({response.status_code}); waiting for the web server to restart")
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
