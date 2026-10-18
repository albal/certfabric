"""Dell iDRAC 8 / 9 / 10 over Redfish.

Imports the certificate and key as a PKCS#12 bundle through Dell's
`DelliDRACCardService.ImportSSLCertificate` action (CertificateType `CustomCertificate`),
then restarts iDRAC so its web server serves it. Host power state is not affected.

Credentials: username + password (an iDRAC user with Configure Manager privilege).
Options:
  manager_id       default `iDRAC.Embedded.1`
  reset            restart iDRAC after the import (default true; the cert is not served until then)
  verify_timeout   seconds to wait for iDRAC to come back serving it (default 300)
"""

from __future__ import annotations

import asyncio
import base64

import httpx

from certfabric.plugins.base import BaseDevicePlugin, PluginError, PluginValidationResult

TIMEOUT_SECONDS = 60


class DellIdracRedfishPlugin(BaseDevicePlugin):
    plugin_id = "dell_idrac_redfish"
    plugin_name = "Dell iDRAC (Redfish)"
    target_category = "bmc"
    supported_models = ["iDRAC 8", "iDRAC 9", "iDRAC 10"]

    @property
    def _manager(self) -> str:
        return str(self.options.get("manager_id", "iDRAC.Embedded.1"))

    def _client(self) -> httpx.AsyncClient:
        creds = self.credentials
        if not (creds.username and creds.password):
            raise PluginError("An iDRAC username and password are required")
        # iDRAC's current certificate is the one being replaced, so it cannot be trusted.
        return httpx.AsyncClient(
            base_url=f"https://{self.host}:{self.port}",
            auth=(creds.username, creds.password),
            verify=False,
            timeout=TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )

    @staticmethod
    def _check(response: httpx.Response, action: str) -> None:
        if response.status_code == 401:
            raise PluginError("iDRAC rejected the username or password")
        if response.status_code >= 400:
            try:
                messages = response.json()["error"]["@Message.ExtendedInfo"]
                detail = "; ".join(m.get("Message", "") for m in messages)
            except (ValueError, KeyError, TypeError):
                detail = response.text[:200]
            raise PluginError(f"{action} failed ({response.status_code}): {detail}")

    async def test_connection(self) -> PluginValidationResult:
        try:
            async with self._client() as client:
                response = await client.get(f"/redfish/v1/Managers/{self._manager}")
                self._check(response, "Reading the iDRAC manager")
                manager = response.json()
        except PluginError as exc:
            return PluginValidationResult(success=False, message=str(exc))
        except httpx.HTTPError as exc:
            return PluginValidationResult(success=False, message=f"iDRAC unreachable: {exc}")
        model = manager.get("Model", "iDRAC")
        firmware = manager.get("FirmwareVersion", "unknown")
        return PluginValidationResult(
            success=True, message=f"{model}, firmware {firmware}", details={"model": model, "firmware": firmware}
        )

    async def deploy_certificate(
        self, cert_pem: str, privkey_pem: str, fullchain_pem: str, pfx_bundle: bytes, pfx_password: str | None
    ) -> bool:
        service = f"/redfish/v1/Dell/Managers/{self._manager}/DelliDRACCardService"
        try:
            async with self._client() as client:
                self.log("Importing the certificate into iDRAC")
                response = await client.post(
                    f"{service}/Actions/DelliDRACCardService.ImportSSLCertificate",
                    json={
                        "CertificateType": "CustomCertificate",
                        "SSLCertificateFile": base64.b64encode(pfx_bundle).decode(),
                        "Passphrase": pfx_password or "",
                    },
                )
                self._check(response, "Certificate import")
                if self.options.get("reset", True):
                    self.log("Restarting iDRAC so its web server serves the new certificate")
                    response = await client.post(
                        f"/redfish/v1/Managers/{self._manager}/Actions/Manager.Reset",
                        json={"ResetType": "GracefulRestart"},
                    )
                    self._check(response, "iDRAC restart")
        except httpx.HTTPError as exc:
            raise PluginError(f"iDRAC unreachable: {exc}") from None
        return True

    async def post_deployment_verify(self, expected_fingerprint: str) -> bool:
        """iDRAC takes minutes to restart; poll until it serves the new certificate."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + float(self.options.get("verify_timeout", 300))
        while True:
            if await self.served_fingerprint() == expected_fingerprint:
                return True
            if loop.time() >= deadline:
                return False
            await asyncio.sleep(5 if deadline - loop.time() > 5 else 0.2)
